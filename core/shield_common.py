# -*- coding: utf-8 -*-
"""
OhmShield 共用：設定載入、檔案鎖、原子寫檔、封鎖清單操作。
所有會「寫資料」的動作（引擎巡檢、封鎖／解封、修補）都經過這裡的鎖，
視窗程式和 OSCLAW 兩個入口同時按也不會互相蓋掉。 MIT License.
"""
import os, sys, json, time, datetime, re, ipaddress, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)   # 專案根目錄（core 的上一層）


def config_path():
    return os.environ.get("OGS_CONFIG") or os.path.join(ROOT, "config.json")


def load_config():
    p = config_path()
    try:
        with open(p, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    d = os.path.dirname(os.path.abspath(p))
    for k in ("visit_log", "blocklist", "ip_notes", "engine_log", "vuln_report", "vuln_log", "scan_root",
              "secguard_report", "status_file", "lock_dir"):
        v = cfg.get(k)
        if isinstance(v, str) and v and not os.path.isabs(v):
            cfg[k] = os.path.join(d, v)
    cfg.setdefault("visit_log", os.path.join(d, "visits.jsonl"))
    cfg.setdefault("blocklist", os.path.join(d, "blocked_ips.json"))
    cfg.setdefault("ip_notes", os.path.join(d, "ip_notes.json"))
    cfg.setdefault("vuln_report", os.path.join(d, "vuln_watch.json"))
    cfg.setdefault("status_file", os.path.join(d, "shield_status.json"))
    cfg.setdefault("lock_dir", os.path.join(d, ".locks"))
    cfg["_dir"] = d
    return cfg


CFG = load_config()


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(p, data, indent=1):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=indent)
    os.replace(tmp, p)


class Lock:
    """跨行程檔案鎖：O_EXCL 建檔；超過 stale 秒數的舊鎖（行程當掉留下的）自動清掉。"""

    def __init__(self, name, timeout=0, stale=3600):
        os.makedirs(CFG["lock_dir"], exist_ok=True)
        self.path = os.path.join(CFG["lock_dir"], name + ".lock")
        self.timeout, self.stale, self.fd = timeout, stale, None

    def acquire(self):
        t0 = time.time()
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, ("%d %s" % (os.getpid(), now_s())).encode())
                return True
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > self.stale:
                        os.remove(self.path)
                        continue
                except OSError:
                    pass
                if time.time() - t0 >= self.timeout:
                    return False
                time.sleep(0.2)

    def release(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
                os.remove(self.path)
            except OSError:
                pass
            self.fd = None

    def held(self):
        return os.path.exists(self.path) and time.time() - os.path.getmtime(self.path) <= self.stale

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("busy:" + os.path.basename(self.path))
        return self

    def __exit__(self, *a):
        self.release()


def valid_ip(ip):
    try:
        ipaddress.ip_address((ip or "").strip())
        return True
    except ValueError:
        return False


def block_ip(ip, reason="manual", note=""):
    if not valid_ip(ip):
        raise ValueError("IP 格式不正確")
    with Lock("blocklist", timeout=10, stale=60):
        bl = load_json(CFG["blocklist"], {})
        bl[ip] = {"blocked_at": now_s(), "reason": reason, "note": (note or "")[:200]}
        save_json(CFG["blocklist"], bl, indent=2)
    return True


def unblock_ip(ip):
    with Lock("blocklist", timeout=10, stale=60):
        bl = load_json(CFG["blocklist"], {})
        bl.pop(ip, None)
        save_json(CFG["blocklist"], bl, indent=2)
    return True


def engine_python():
    """背景執行引擎用的直譯器（打包成 exe 時 sys.executable 是 exe 本身，不能拿來跑 .py）"""
    p = CFG.get("engine_python")
    if p and os.path.exists(p):
        return p
    exe = sys.executable
    if getattr(sys, "frozen", False):
        return "pythonw" if os.name == "nt" else "python3"
    if os.name == "nt" and exe.lower().endswith("python.exe") and os.path.exists(exe[:-10] + "pythonw.exe"):
        return exe[:-10] + "pythonw.exe"
    return exe


def spawn(script, *args):
    """背景啟動引擎（不跳視窗、不等它跑完）"""
    flags = 0
    if os.name == "nt":
        flags = 0x08000000 | 0x00000200   # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    env = dict(os.environ, OGS_CONFIG=config_path())
    subprocess.Popen([engine_python(), os.path.join(HERE, script), *args], cwd=HERE, env=env,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, close_fds=True)
