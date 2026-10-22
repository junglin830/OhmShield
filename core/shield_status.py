# -*- coding: utf-8 -*-
"""
OhmShield 總狀態：把「網頁門牌（IP 情報）」「漏洞情報」「電腦（SecGuard 報告，選填）」合成一個分數、
紅黃綠燈與待處理清單，寫到 shield_status.json。視窗程式的常駐圖示、OSCLAW、LINE 查詢都讀這一份。
  python shield_status.py          # 重算並印出
MIT License.
"""
import os, sys, json, time, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shield_common import CFG, load_json, save_json, now_s, Lock

VERSION = "1.2.0"


def _age_h(ts):
    try:
        return (time.time() - datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp()) / 3600
    except Exception:
        return None


def build(write=True):
    notes = load_json(CFG["ip_notes"], {})
    vw = load_json(CFG["vuln_report"], {})
    bl = load_json(CFG["blocklist"], {})
    sg = load_json(CFG.get("secguard_report", ""), None) if CFG.get("secguard_report") else None
    todo, lines = [], {}

    # ── 網頁門牌 ──
    nm = notes.get("_meta", {})
    ips = notes.get("ips", {})
    web = 100
    age = _age_h(nm.get("last_run", ""))
    open_mal = [ip for ip, v in ips.items() if v.get("kind") == "malicious" and not v.get("blocked") and ip not in bl]
    if age is None:
        web -= 30
        todo.append({"line": "web", "level": "warn", "text": "IP 情報引擎尚未執行過"})
    elif age > 3:
        web -= 20
        todo.append({"line": "web", "level": "warn", "text": "IP 情報引擎 %.0f 小時沒有巡檢（排程可能停了）" % age})
    if open_mal:
        web -= min(40, 15 * len(open_mal))
        todo.append({"line": "web", "level": "alert", "text": "%d 個惡意 IP 尚未封鎖：%s" % (len(open_mal), "、".join(open_mal[:3]))})
    counts = nm.get("counts", {})
    lines["web"] = {"score": max(0, web), "ips": nm.get("total", 0), "blocked": len(bl), "malicious": counts.get("malicious", 0),
                    "humans": counts.get("human", 0), "last_run": nm.get("last_run", ""),
                    "auto_blocked_last_run": len(nm.get("auto_blocked_last_run", []) or [])}

    # ── 漏洞情報 ──
    vm = vw.get("_meta", {})
    vuln = 100
    F = vw.get("findings", []) or []
    exp = [f for f in F if f.get("exposed")]
    crit = sorted({f["component"] for f in exp if f.get("severity") == "CRITICAL"})
    high = sorted({f["component"] for f in exp if f.get("severity") == "HIGH"})
    vuln -= min(45, 15 * len(crit)) + min(25, 3 * len(high))
    vage = _age_h(vm.get("last_run", ""))
    if vage is None:
        vuln = min(vuln, 70)
        todo.append({"line": "vuln", "level": "warn", "text": "漏洞情報尚未執行過"})
    elif vage > 30:
        vuln -= 15
        todo.append({"line": "vuln", "level": "warn", "text": "漏洞情報 %.0f 小時沒有巡檢" % vage})
    if crit:
        todo.append({"line": "vuln", "level": "alert", "text": "對外服務有嚴重漏洞未修：%s" % "、".join(crit[:5])})
    local_n = len([f for f in F if not f.get("exposed")])
    if local_n:
        todo.append({"line": "vuln", "level": "info", "text": "本機工具環境（不對外）還有 %d 筆已知漏洞，不影響對外安全，有空再整理" % local_n})
    held = (vw.get("patch") or {}).get("held") or []
    if held:
        todo.append({"line": "vuln", "level": "info", "text": "%d 個套件需人工評估（跨大版本／核心套件）：%s" % (len(held), "、".join(h["pkg"] for h in held[:5]))})
    for n in vw.get("notes", []) or []:
        if n.startswith("⚠"):
            vuln -= 10
            todo.append({"line": "vuln", "level": "alert", "text": n.lstrip("⚠ ")})
    lines["vuln"] = {"score": max(0, vuln), "packages": vm.get("packages_checked", 0), "exposed": vm.get("exposed_findings", 0), "local": local_n,
                     "exposed_packages": vm.get("exposed_packages"), "exposure_mode": vm.get("exposure_mode"),
                     "critical_pkgs": crit, "high_pkgs": len(high), "kev": vm.get("kev_recent", 0), "last_run": vm.get("last_run", ""),
                     "patched_last": len((vw.get("patch") or {}).get("patched") or [])}

    # ── 電腦（SecGuard 報告，選填）──
    if sg:
        pc = sg.get("score")
        lines["pc"] = {"score": pc if isinstance(pc, (int, float)) else None, "last_run": sg.get("ts", ""),
                       "alerts": (sg.get("counts") or {}).get("alert", 0), "warns": (sg.get("counts") or {}).get("warn", 0)}
        for f in sg.get("findings", []) or []:
            if f.get("level") in ("alert", "warn"):
                todo.append({"line": "pc", "level": f["level"], "text": f.get("title", "")})

    scores = [v["score"] for v in lines.values() if isinstance(v.get("score"), (int, float))]
    total = round(0.4 * min(scores) + 0.6 * (sum(scores) / len(scores))) if scores else 0
    level = "green" if total >= 85 and not any(t["level"] == "alert" for t in todo) else "yellow" if total >= 60 else "red"
    order = {"alert": 0, "warn": 1, "info": 2}
    todo.sort(key=lambda t: order.get(t["level"], 3))
    st = {"version": VERSION, "ts": now_s(), "score": total, "level": level, "lines": lines, "todo": todo[:20],
          "summary": summary_text(total, level, lines, todo)}
    if write:
        try:
            with Lock("status", timeout=5, stale=60):
                save_json(CFG["status_file"], st)
        except Exception:
            pass
    return st


def summary_text(total, level, lines, todo):
    lamp = {"green": "🟢 正常", "yellow": "🟡 注意", "red": "🔴 警報"}[level]
    w, v = lines.get("web", {}), lines.get("vuln", {})
    parts = ["資安總分 %d（%s）" % (total, lamp),
             "門牌：%d 個 IP 已辨識、%d 個已封鎖" % (w.get("ips", 0), w.get("blocked", 0)),
             "漏洞：對外 %d 筆%s" % (v.get("exposed", 0), "，嚴重：" + "、".join(v["critical_pkgs"][:3]) if v.get("critical_pkgs") else "")]
    if "pc" in lines and lines["pc"].get("score") is not None:
        parts.append("電腦：%s 分" % lines["pc"]["score"])
    act = [t["text"] for t in todo if t["level"] == "alert"][:2]
    if act:
        parts.append("待處理：" + "；".join(act))
    return "\n".join(parts)


if __name__ == "__main__":
    s = build()
    print(s["summary"])
