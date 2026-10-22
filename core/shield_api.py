# -*- coding: utf-8 -*-
"""
OhmShield 唯一的 API 實作。視窗程式（app/ 的本機伺服器）和 OSCLAW（osclaw/ 的 Flask 模組）
都只是把 /api/shield/<路徑> 轉進 handle()，所以兩邊的行為、資料、權限規則永遠一致。

  GET  ui          唯一的介面頁（ui/shield.html）
  GET  status      總狀態（即時重算）
  GET  visits      訪客紀錄（可加 ?tail=N 只取最後 N 行）
  GET  notes       IP 身分備註
  GET  blocklist   封鎖清單
  GET  vuln        漏洞情報報告
  GET  secguard    電腦資安報告（OhmSecGuard 格式，選填）
  GET  jobs        背景工作是否在跑
  POST block       {"ip","note"}
  POST unblock     {"ip"}
  POST scan        {"target": "ip" | "vuln"}
  POST patch       {}        漏洞巡檢＋安全自動修補
權限由外殼負責（視窗程式：本機 token；OSCLAW：老闆登入）。 MIT License.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shield_common import CFG, ROOT, load_json, block_ip, unblock_ip, valid_ip, spawn, Lock

VERSION = "1.0.0"
UI_FILE = os.path.join(ROOT, "ui", "shield.html")


def _json(obj, code=200):
    return code, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _file(path, ctype, missing=None):
    try:
        with open(path, "rb") as f:
            return 200, ctype, f.read()
    except OSError:
        if missing is not None:
            return _json(missing)
        return _json({"ok": False, "error": "not found"}, 404)


def _tail(path, n):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block, data = 65536, b""
            while size > 0 and data.count(b"\n") <= n:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
        return 200, "text/plain; charset=utf-8", b"\n".join(data.splitlines()[-n:]) + b"\n"
    except OSError:
        return 200, "text/plain; charset=utf-8", b""


def handle(method, path, query=None, body=None):
    """path：/api/shield/ 之後的部分。回傳 (http_code, content_type, bytes)"""
    query = query or {}
    path = (path or "").strip("/")
    try:
        if method == "GET":
            if path in ("", "ui"):
                return _file(UI_FILE, "text/html; charset=utf-8")
            if path == "status":
                import shield_status
                st = shield_status.build(write=True)
                st["ui"] = {"owner": CFG.get("owner_label", "站長"), "links": CFG.get("ui_links", {})}
                return _json(st)
            if path == "visits":
                n = int(query.get("tail", 0) or 0)
                if n > 0:
                    return _tail(CFG["visit_log"], min(n, 200000))
                return _file(CFG["visit_log"], "text/plain; charset=utf-8", missing="")
            if path == "notes":
                return _file(CFG["ip_notes"], "application/json; charset=utf-8", missing={})
            if path == "blocklist":
                return _file(CFG["blocklist"], "application/json; charset=utf-8", missing={})
            if path == "vuln":
                return _file(CFG["vuln_report"], "application/json; charset=utf-8", missing={})
            if path == "secguard":
                if not CFG.get("secguard_report"):
                    return _json({"ok": False, "error": "未設定 secguard_report"})
                return _json({"ok": True, "report": load_json(CFG["secguard_report"], None)})
            if path == "jobs":
                return _json({"ip_intel": Lock("ip_intel", stale=1800).held(), "vuln_watch": Lock("vuln_watch", stale=3 * 3600).held()})
            if path == "version":
                return _json({"api": VERSION})
        elif method == "POST":
            b = body or {}
            if path == "block":
                ip = (b.get("ip") or "").strip()
                if not valid_ip(ip):
                    return _json({"ok": False, "error": "IP 格式不正確"}, 400)
                if _is_self(ip):
                    return _json({"ok": False, "error": "這是自家／老闆的 IP，不能封鎖"}, 400)
                block_ip(ip, "manual", b.get("note") or "")
                return _json({"ok": True})
            if path == "unblock":
                unblock_ip((b.get("ip") or "").strip())
                return _json({"ok": True})
            if path == "scan":
                t = b.get("target") or "ip"
                if t == "ip":
                    if Lock("ip_intel", stale=1800).held():
                        return _json({"ok": True, "busy": True})
                    spawn("ip_intel.py", "run")
                elif t == "vuln":
                    if Lock("vuln_watch", stale=3 * 3600).held():
                        return _json({"ok": True, "busy": True})
                    spawn("vuln_watch.py", "run", "--no-notify")
                else:
                    return _json({"ok": False, "error": "target 只能是 ip 或 vuln"}, 400)
                return _json({"ok": True, "started": t})
            if path == "patch":
                if Lock("vuln_watch", stale=3 * 3600).held():
                    return _json({"ok": True, "busy": True})
                spawn("vuln_watch.py", "run", "--patch", "--no-notify")
                return _json({"ok": True, "started": "patch"})
        return _json({"ok": False, "error": "unknown endpoint"}, 404)
    except Exception as e:
        return _json({"ok": False, "error": str(e)[:300]}, 500)


def _is_self(ip):
    v = (load_json(CFG["ip_notes"], {}).get("ips") or {}).get(ip) or {}
    return v.get("kind") in ("self", "boss")
