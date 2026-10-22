# -*- coding: utf-8 -*-
"""
OhmShield 桌面視窗程式（外殼）。
- 在 127.0.0.1 隨機埠開一個只給自己用的小伺服器，把 /api/shield/* 轉給 core/shield_api.handle()
  ——跟 OSCLAW 用的是同一份 API、同一個介面頁、同一份資料。
- 每次啟動產生隨機 token，只有帶 token 的請求能讀寫資料（擋掉其他網頁或程式偷打 localhost）。
- 右下角盾牌常駐：綠／黃／紅＝總狀態，滑過看分數，點兩下開視窗；關視窗只是縮回常駐。
- 不依賴網站伺服器或 OSCLAW：直接讀寫本機檔案，離線也能用。
相依：pywebview（BSD）、pystray（LGPL-3.0）、Pillow（MIT-CMU）。 MIT License.
"""
import os, sys, json, time, secrets, threading, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

APP_VERSION = "1.0.0"
APP_NAME = "OhmShield 歐姆資安中心"


def _find_root():
    """往上找有 core/shield_api.py 的專案根目錄（原始碼執行或 exe 放在專案裡都適用）"""
    starts = [os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))]
    if getattr(sys, "_MEIPASS", None):
        starts.append(sys._MEIPASS)
    for s in starts:
        d = s
        for _ in range(5):
            if os.path.exists(os.path.join(d, "core", "shield_api.py")):
                return d
            d = os.path.dirname(d)
    return starts[-1]


ROOT = _find_root()
if os.path.exists(os.path.join(ROOT, "config.json")):
    os.environ.setdefault("OGS_CONFIG", os.path.join(ROOT, "config.json"))
sys.path.insert(0, os.path.join(ROOT, "core"))
import shield_api  # noqa: E402

TOKEN = secrets.token_urlsafe(24)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _route(self, method):
        u = urllib.parse.urlsplit(self.path)
        if not u.path.startswith("/api/shield/"):
            return self._send(404, "text/plain", b"not found")
        sub = u.path[len("/api/shield/"):]
        # 介面頁本身沒有資料，可以不帶 token；其餘一律要 token
        if sub not in ("", "ui") and self.headers.get("X-Shield-Token") != TOKEN:
            return self._send(403, "application/json", b'{"ok":false,"error":"forbidden"}')
        if method == "POST" and self.headers.get("Origin") not in (None, "null", "http://%s:%d" % self.server.server_address[:2]):
            return self._send(403, "application/json", b'{"ok":false,"error":"bad origin"}')
        body = None
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            except Exception:
                body = {}
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        code, ctype, data = shield_api.handle(method, sub, q, body)
        self._send(code, ctype, data)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def status():
    try:
        import shield_status
        return shield_status.build(write=False)
    except Exception:
        return {"score": 0, "level": "red", "summary": "讀不到狀態"}


COLORS = {"green": (48, 209, 88), "yellow": (255, 204, 0), "red": (255, 69, 58)}


def make_icon(level):
    from PIL import Image, ImageDraw
    sz = 64
    im = Image.new("RGBA", (sz, sz), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = COLORS.get(level, COLORS["yellow"])
    shield = [(32, 4), (58, 13), (58, 31), (52, 46), (32, 60), (12, 46), (6, 31), (6, 13)]
    d.polygon(shield, fill=c + (255,))
    d.line([(20, 33), (29, 42), (45, 23)], fill=(255, 255, 255, 255), width=6, joint="curve")
    return im


def single_instance():
    if os.name != "nt":
        return True
    import ctypes
    ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\OhmShieldApp")
    return ctypes.windll.kernel32.GetLastError() != 183   # ERROR_ALREADY_EXISTS


def main():
    if not single_instance():
        return
    import webview
    import pystray
    srv = start_server()
    url = "http://127.0.0.1:%d/api/shield/ui#t=%s" % (srv.server_address[1], TOKEN)
    start_hidden = "--hidden" in sys.argv
    win = webview.create_window(APP_NAME, url, width=1320, height=900, min_size=(420, 600), hidden=start_hidden,
                                background_color="#07080b", text_select=True)
    state = {"quit": False, "level": None}

    def on_closing():
        if state["quit"]:
            return True
        win.hide()          # 關視窗＝縮回常駐圖示
        return False

    win.events.closing += on_closing

    def show(icon=None, item=None):
        win.show()
        win.restore()

    def scan(target):
        def _f(icon=None, item=None):
            shield_api.handle("POST", "patch" if target == "patch" else "scan", {}, {"target": target})
            icon and icon.notify("已開始" + {"ip": "門牌巡檢", "vuln": "漏洞巡檢", "patch": "巡檢＋安全修補"}[target], APP_NAME)
        return _f

    def quit_app(icon, item):
        state["quit"] = True
        icon.stop()
        win.destroy()

    st = status()
    icon = pystray.Icon("OhmShield", make_icon(st.get("level")), "%s｜總分 %s" % (APP_NAME, st.get("score")),
                        menu=pystray.Menu(
                            pystray.MenuItem("開啟資安中心", show, default=True),
                            pystray.MenuItem("巡檢門牌", scan("ip")),
                            pystray.MenuItem("漏洞巡檢", scan("vuln")),
                            pystray.MenuItem("巡檢＋安全修補", scan("patch")),
                            pystray.Menu.SEPARATOR,
                            pystray.MenuItem("結束 OhmShield", quit_app)))

    def refresher():
        while not state["quit"]:
            s = status()
            lv = s.get("level")
            try:
                icon.title = ("%s｜總分 %s\n%s" % (APP_NAME, s.get("score"), (s.get("summary") or "").split("\n")[0]))[:127]
                if lv != state["level"]:
                    icon.icon = make_icon(lv)
                    if state["level"] is not None and lv == "red":
                        icon.notify("資安狀態變成紅燈，點開看待處理事項", APP_NAME)
                    state["level"] = lv
            except Exception:
                pass
            for _ in range(60):
                if state["quit"]:
                    break
                time.sleep(1)

    def after_start():
        icon.run_detached()
        threading.Thread(target=refresher, daemon=True).start()

    webview.start(after_start, private_mode=False)


if __name__ == "__main__":
    main()
