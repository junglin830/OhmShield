# -*- coding: utf-8 -*-
"""
OhmShield · Vuln Watch — 「我們實際在跑的軟體，有沒有中已知漏洞？」每天自動回答，並在安全範圍內自動修補。
Daily answer to "is anything we actually run affected by a known vulnerability?" — plus safe auto-patching.

  1. Inventory: pip packages of the exposed Python (+ other interpreters / .venv under scan_root),
     npm packages from package-lock.json under scan_root, binaries (Node.js, cloudflared, Git, Python,
     Chrome, OS) and server software that should NOT be there (PHP / Apache / Nginx / XAMPP).
  2. OSV.dev batch lookup (PyPI / npm / Go) → known vulns + fixed versions.
  3. CISA KEV (Known Exploited Vulnerabilities) entries added in the last 30 days matching products you have.
  4. Writes vuln_watch.json (dashboard.html reads it).
  5. patch: upgrades vulnerable packages of the *exposed* interpreter one at a time with --no-deps,
     only within the same major version, after a pip-freeze backup; import test + `pip check` diff per
     package, rolls back that package on any new conflict, and a final safety net restores anything else
     that changed. Cross-major / core packages are listed as "needs review" and never touched.

  python vuln_watch.py run [--patch] [--no-notify]
  python vuln_watch.py patch [--dry]
  python vuln_watch.py show
Standard library only. MIT License.
"""
import sys, os, re, json, glob, time, datetime, subprocess, urllib.request, collections

VERSION = "1.4.1"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shield_common import CFG, Lock   # 設定與鎖（兩個入口共用）
_abs = lambda p: p
ROOT = CFG.get("scan_root", "")                                    # 掃 .venv / package-lock.json 的根目錄（空＝不掃）
OUT = CFG["vuln_report"]
LOG = CFG.get("vuln_log") or os.path.join(CFG["_dir"], "vuln_watch.log")
CACHE = CFG.get("vuln_cache") or os.path.join(os.path.dirname(OUT), "vuln_watch_cache.json")
SYS_PY = CFG.get("exposed_python", sys.executable)                 # interpreter running your public services (auto-patched)
EXTRA_PY = CFG.get("other_pythons", [])                            # other interpreters to report on (never patched)
UA = "OhmShield-VulnWatch/1.3 (+https://github.com/junglin830/OhmShield)"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
SKIP_DIRS = re.compile(r"[\\/](node_modules|site-packages|\.git|trash|_tmp|backup[^\\/]*)([\\/]|$)", re.I)
if CFG.get("scan_skip_regex"):   # 額外略過的大型資料夾（模型、備份…）
    SKIP_DIRS = re.compile(SKIP_DIRS.pattern[:-len(")([\\\\/]|$)")] + "|" + CFG["scan_skip_regex"] + ")([\\\\/]|$)", re.I)
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "": 0}
KEV_MATCH = [  # (我們的元件, CISA KEV vendorProject/product 關鍵字)
    ("Node.js", r"node\.?js"), ("Python", r"\bpython\b"), ("cloudflared", r"cloudflare"), ("Git", r"^git$|\bgit\b"),
    ("Chrome", r"chrom(e|ium)"), ("Windows", r"microsoft.*windows|windows"), ("PHP", r"\bphp\b"),
    ("Apache", r"apache http"), ("Nginx", r"nginx"), ("7-Zip", r"7-zip"), ("WinRAR", r"winrar|rarlab"),
]


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(m):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (now_s(), m))
    except Exception:
        pass


def sh(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        return (r.stdout or b"").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def http_json(url, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def load(p, d):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return d


def save(p, data):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


# ---------------- 1. 盤點 ----------------
def running_pythons():
    """exposed_python is treated as the interpreter running public services; everything else is report-only."""
    return {SYS_PY.lower(): ["exposed services"], SYS_PY.lower().replace("python.exe", "pythonw.exe"): []}


def _walk(root, depth=4):
    if not root or not os.path.isdir(root):
        return
    base = root.rstrip("\\/").count(os.sep)
    for d, dirs, files in os.walk(root):
        if SKIP_DIRS.search(d + os.sep) or d.count(os.sep) - base >= depth:
            dirs[:] = []
            continue
        yield d, dirs, files


def find_venvs():
    pys = []
    for d, dirs, files in _walk(ROOT, 4):
        for v in (".venv", "venv", "env"):
            if v in dirs:
                for exe in (os.path.join(d, v, "Scripts", "python.exe"), os.path.join(d, v, "bin", "python")):
                    if os.path.exists(exe):
                        pys.append(exe)
    return sorted(set(pys + [p for p in EXTRA_PY if os.path.exists(p)]))


def _norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def pip_list(py):
    """用 importlib.metadata 列套件（uv 建的 venv 沒有 pip，用 pip list 會得到 0 個）"""
    code = ("import json,importlib.metadata as m\n"
            "r={}\n"
            "for d in m.distributions():\n"
            "  n=(d.metadata.get('Name') or '').strip()\n"
            "  if n: r[n]=d.version\n"
            "print(json.dumps(sorted(r.items())))")
    out = sh([py, "-c", code], 120)
    try:
        return [tuple(x) for x in json.loads(out.splitlines()[-1])]
    except Exception:
        return []


def npm_locks():
    locks = [os.path.join(d, "package-lock.json") for d, dirs, files in _walk(ROOT, 5) if "package-lock.json" in files]
    res = []
    for p in sorted(set(locks)):
        d = load(p, {})
        pk = {}
        for k, v in (d.get("packages") or {}).items():
            if not k or not isinstance(v, dict) or not v.get("version"):
                continue
            name = v.get("name") or k.split("node_modules/")[-1]
            pk[name] = v["version"]
        if not pk:
            for name, v in (d.get("dependencies") or {}).items():
                if isinstance(v, dict) and v.get("version"):
                    pk[name] = v["version"]
        if pk:
            res.append((p, sorted(pk.items())))
    return res


def ver_of(args, rx=r"(\d+\.\d+(?:\.\d+)*)"):
    m = re.search(rx, sh(args, 30))
    return m.group(1) if m else ""


def binaries():
    b = {}
    b["Node.js"] = ver_of(["node", "--version"])
    cf = glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\Cloudflare.cloudflared*\cloudflared.exe")) if os.name == "nt" else []
    b["cloudflared"] = ver_of([cf[0], "--version"]) if cf else ver_of(["cloudflared", "--version"])
    b["Git"] = ver_of(["git", "--version"])
    b["Python"] = ver_of([SYS_PY, "--version"])
    chrome = [p for p in (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") if os.path.exists(p)]
    b["Chrome"] = ""
    try:
        import winreg
        for hive, key in ((winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon"), (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Google\Update\Clients\{8A69D345-D564-463c-AFF1-A69D9E530F96}")):
            try:
                with winreg.OpenKey(hive, key) as k:
                    b["Chrome"] = winreg.QueryValueEx(k, "version" if "BLBeacon" in key else "pv")[0]
                    break
            except OSError:
                pass
    except Exception:
        pass
    if not b["Chrome"] and chrome:
        b["Chrome"] = "已安裝"
    try:
        w = sys.getwindowsversion()
        b["Windows"] = "%d.%d.%d" % (w.major, w.minor, w.build)
    except Exception:
        b["Windows"] = ""
    # 不該存在／我們沒用的伺服器軟體：有裝就要列出
    php = sh(["where" if os.name == "nt" else "which", "php"], 15)
    b["PHP"] = ver_of(["php", "-v"]) if php and "php" in php.lower() else ""
    for name, paths in (("Apache", [r"C:\Apache24", r"C:\xampp\apache"]), ("Nginx", [r"C:\nginx"]), ("XAMPP", [r"C:\xampp"])):
        b[name] = "已安裝" if any(os.path.exists(p) for p in paths) else ""
    return b


# ---------------- 2. OSV 比對 ----------------
def osv_batch(queries):
    """queries: [(ecosystem, name, version)] → {index: [vuln ids]}"""
    hits = {}
    for i in range(0, len(queries), 900):
        chunk = queries[i:i + 900]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        try:
            r = http_json("https://api.osv.dev/v1/querybatch", body, 60)
        except Exception as ex:
            log("OSV batch 失敗：%s" % ex)
            continue
        for j, res in enumerate(r.get("results", [])):
            ids = [v["id"] for v in (res.get("vulns") or [])]
            if ids:
                hits[i + j] = ids
        time.sleep(0.5)
    return hits


def osv_detail(vid, cache):
    if vid in cache and time.time() - cache[vid].get("_t", 0) < 7 * 86400:
        return cache[vid]
    try:
        d = http_json("https://api.osv.dev/v1/vulns/" + vid, None, 30)
    except Exception as ex:
        log("OSV detail 失敗 %s：%s" % (vid, ex))
        return cache.get(vid) or {"id": vid}
    sev = ((d.get("database_specific") or {}).get("severity") or "").upper()
    score = ""
    for s in d.get("severity") or []:
        if s.get("type", "").startswith("CVSS"):
            score = s.get("score", "")
    fixed = []
    for a in d.get("affected") or []:
        for rg in a.get("ranges") or []:
            for ev in rg.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    aliases = [x for x in (d.get("aliases") or []) if x.startswith("CVE-")]
    info = {"id": vid, "cve": aliases[:2], "severity": sev, "cvss": score, "summary": (d.get("summary") or d.get("details") or "")[:200],
            "fixed": sorted(set(fixed))[-3:], "published": (d.get("published") or "")[:10], "_t": time.time()}
    cache[vid] = info
    return info


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def pick_fixed(cur, fixed):
    """挑「高於目前版本」的最小修補版本"""
    c = ver_tuple(cur)
    cands = sorted((ver_tuple(f), f) for f in fixed if ver_tuple(f) > c)
    return cands[0][1] if cands else (fixed[-1] if fixed else "")


# ---------------- 3. CISA KEV ----------------
def kev_recent(bins, days=30):
    try:
        d = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", None, 60)
    except Exception as ex:
        log("KEV 失敗：%s" % ex)
        return [], ""
    cut = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    have = {k for k, v in bins.items() if v}
    res = []
    for v in d.get("vulnerabilities", []):
        if (v.get("dateAdded") or "") < cut:
            continue
        txt = (v.get("vendorProject", "") + " " + v.get("product", "")).lower()
        for comp, rx in KEV_MATCH:
            if comp in have and re.search(rx, txt, re.I):
                res.append({"component": comp, "version": bins.get(comp, ""), "cve": v.get("cveID"), "name": v.get("vulnerabilityName", "")[:120],
                            "added": v.get("dateAdded"), "due": v.get("dueDate"), "action": (v.get("requiredAction") or "")[:160],
                            "ransomware": v.get("knownRansomwareCampaignUse", "")})
                break
    return res, d.get("catalogVersion", "")


# ---------------- 主流程 ----------------
def run(notify=True, baseline=None):
    t0 = time.time()
    cache = load(CACHE, {})
    prev = load(OUT, {})
    running = running_pythons()
    pys = [SYS_PY] + find_venvs()
    try:
        import exposure
        used = exposure.analyze()          # {套件: [用到它的對外服務]}；None＝沒設定，整個系統 Python 視為對外
    except Exception as ex:
        log("對外暴露分析失敗，改用保守做法（整個系統 Python 視為對外）：%r" % ex)
        used = None
    exp_envs = {p.lower() for p in CFG.get("exposed_envs", [])}
    envs = []
    queries, qmeta = [], []
    for py in pys:
        if not os.path.exists(py):
            continue
        pkgs = pip_list(py)
        live = running.get(py.lower(), [])
        live += running.get(py.lower().replace("python.exe", "pythonw.exe"), [])
        env_exposed = bool(live) or py.lower() in exp_envs
        envs.append({"type": "python", "path": py, "packages": len(pkgs), "running": sorted(set(live))[:12], "exposed": env_exposed,
                     "exposed_packages": (len([1 for n, _ in pkgs if _norm(n) in used]) if (used is not None and py == SYS_PY) else None)})
        for n, v in pkgs:
            if py == SYS_PY and used is not None:
                ex_ = _norm(n) in used
            else:
                ex_ = env_exposed
            queries.append(("PyPI", n, v))
            qmeta.append((py, "python", n, v, ex_))
    for lock, pk in npm_locks():
        envs.append({"type": "npm", "path": lock, "packages": len(pk), "running": [], "exposed": False})
        for n, v in pk:
            queries.append(("npm", n, v))
            qmeta.append((lock, "npm", n, v, False))
    bins = binaries()
    if bins.get("cloudflared"):
        queries.append(("Go", "github.com/cloudflare/cloudflared", "v" + bins["cloudflared"] if not bins["cloudflared"].startswith("v") else bins["cloudflared"]))
        qmeta.append(("cloudflared.exe", "binary", "cloudflared", bins["cloudflared"], True))

    hits = osv_batch(queries)
    findings = []
    for i, ids in hits.items():
        where, typ, name, ver, exposed = qmeta[i]
        for vid in ids[:12]:
            info = osv_detail(vid, cache)
            fx = pick_fixed(ver, info.get("fixed") or [])
            findings.append({"component": name, "type": typ, "version": ver, "where": where, "exposed": exposed,
                             "used_by": (used or {}).get(_norm(name), []) if (used is not None and where == SYS_PY) else [],
                             "id": vid, "cve": info.get("cve", []), "severity": info.get("severity", ""), "cvss": info.get("cvss", ""),
                             "summary": info.get("summary", ""), "fixed": fx, "published": info.get("published", ""),
                             "fix_cmd": ('"%s" -m pip install -U "%s>=%s"' % (where, name, fx)) if typ == "python" and fx else
                                        ("npm i %s@%s（在 %s 目錄）" % (name, fx, os.path.dirname(where)) if typ == "npm" and fx else "")})
    findings.sort(key=lambda f: (-int(f["exposed"]), -SEV_RANK.get(f["severity"], 0), f["component"]))
    kev, kev_ver = kev_recent(bins)

    # 新增的才通知（以 id+where 為鍵）
    base = baseline if baseline is not None else prev   # 修補模式：拿「修補前」那份比，修好的不通知、沒修好的新漏洞才通知
    old_keys = {(f["id"], f["where"]) for f in base.get("findings", [])}
    new = [f for f in findings if (f["id"], f["where"]) not in old_keys]
    urgent = [f for f in new if f["exposed"] and f["severity"] in ("CRITICAL",)]
    old_kev = {k["cve"] for k in base.get("kev", [])}
    new_kev = [k for k in kev if k["cve"] not in old_kev and k["component"] in ("cloudflared", "Node.js", "Python", "PHP", "Apache", "Nginx")]

    sev_count = collections.Counter(f["severity"] or "UNKNOWN" for f in findings)
    meta = {"version": VERSION, "last_run": now_s(), "took_sec": round(time.time() - t0, 1), "packages_checked": len(queries),
            "envs": len(envs), "findings": len(findings), "exposed_findings": sum(1 for f in findings if f["exposed"]),
            "exposure_mode": "import-closure" if used is not None else "whole-interpreter", "exposed_packages": len(used or {}),
            "by_severity": dict(sev_count), "kev_catalog": kev_ver, "kev_recent": len(kev), "new_this_run": len(new)}
    out = {"_meta": meta, "binaries": bins, "envs": envs, "findings": findings[:3000], "kev": kev, "patch": prev.get("patch"),
           "notes": (["作業系統有近期已遭利用漏洞：確認 Windows Update／系統更新已裝 KEV 新增日之後的安全更新"] if any(k["component"] == "Windows" for k in kev) else []) + ["PHP 未安裝：不受 PHP 類漏洞（例如 2026-10 PHP2Shell CVE-2026-109618/109619）影響" if not bins.get("PHP") else "⚠ 偵測到 PHP %s，需確認是否 ≥ 8.5.12／8.4.27／8.3.36／8.2.35" % bins["PHP"]]}
    save(OUT, out)
    save(CACHE, cache)
    log("run v%s：%d 套件、%d 環境、漏洞 %d（對外 %d）、KEV 近30天相關 %d、新增 %d，%.1fs" % (
        VERSION, len(queries), len(envs), len(findings), meta["exposed_findings"], len(kev), len(new), time.time() - t0))

    if notify and (urgent or new_kev):
        hook = CFG.get("notify_command")   # e.g. ["notify-send", "OhmGateShield"] — the message is appended as last arg
        for msg in ["%s %s 有嚴重漏洞 %s，修補版 %s" % (f["component"], f["version"], (f["cve"] or [f["id"]])[0], f["fixed"] or "?") for f in urgent[:3]] + \
                   ["%s 出現已遭攻擊利用的漏洞 %s（CISA KEV）" % (k["component"], k["cve"]) for k in new_kev[:2]]:
            log("ALERT " + msg)
            if hook:
                sh((hook if isinstance(hook, list) else [hook]) + [msg], 30)


# ---------------- 4. 自動修補（只修 exposed_python，安全範圍內） ----------------
BACKUP_DIR = CFG.get("vuln_backup_dir") or os.path.join(os.path.dirname(OUT), "vuln_watch_backup")
PATCH_HOLD = {"pip", "setuptools", "torch", "torchvision", "torchaudio", "numpy", "transformers", "diffusers", "gradio", "gradio-client", "fastapi", "starlette", "pydantic", "pydantic-core"}  # 牽動太大：只列出，不自動


def _py_json(py, code, timeout=120):
    out = sh([py, "-c", code], timeout)
    try:
        return json.loads(out.splitlines()[-1]) if out else None
    except Exception:
        return None


def _pip_check(py):
    out = sh([py, "-m", "pip", "check", "--disable-pip-version-check"], 180)
    return {l.strip() for l in out.splitlines() if l.strip() and not l.startswith("WARNING")}


def _major(v):
    t = ver_tuple(v)
    # 0.x 套件：把「次版號」當大版本（0.14 → 0.16 視為跨版）
    return t[:2] if t and t[0] == 0 else t[:1]


def patch(dry=False):
    data = load(OUT, {})
    py = SYS_PY
    need = collections.defaultdict(list)
    for f in data.get("findings", []):
        if f.get("type") == "python" and f.get("where", "").lower() == py.lower() and f.get("exposed") and f.get("fixed"):
            need[f["component"]].append(f)
    if not need:
        data["patch"] = {"ts": now_s(), "patched": [], "failed": [], "rolled_back": [], "held": [], "plan": [], "dry": dry,
                         "note": "對外服務沒有需要修補的已知漏洞"}
        save(OUT, data)
        log("patch：對外服務沒有要修的")
        return data["patch"]
    names = sorted(need)
    meta = _py_json(py, "import json,importlib.metadata as m;r={}\n"
                        "for n in %r:\n"
                        "  try:\n"
                        "    d=m.distribution(n);fs=[str(x) for x in (d.files or [])]\n"
                        "    r[n]={'v':d.version,'bin':any(x.lower().endswith(('.pyd','.dll','.so')) for x in fs),'top':(d.read_text('top_level.txt') or '').split()}\n"
                        "  except Exception as e: r[n]={'err':str(e)}\n"
                        "print(json.dumps(r))" % names) or {}
    plan, held = [], []
    for n in names:
        cur = (meta.get(n) or {}).get("v") or need[n][0]["version"]
        fixes = sorted({f["fixed"] for f in need[n] if f.get("fixed")}, key=ver_tuple)
        if n.lower() in ("certifi", "tzdata"):   # 日期版號（CA 憑證庫等）：一律升到最新修補版
            same = [x for x in fixes if ver_tuple(x) > ver_tuple(cur)]
        else:
            same = [x for x in fixes if _major(x) == _major(cur) and ver_tuple(x) > ver_tuple(cur)]
        cross = [x for x in fixes if _major(x) != _major(cur)]
        info = meta.get(n) or {}
        if n.lower() in PATCH_HOLD:
            held.append({"pkg": n, "cur": cur, "fix": fixes[-1] if fixes else "", "why": "核心套件，牽動太大，不自動升級"})
        elif same:
            # 含編譯檔（.pyd）的也嘗試：檔案若被執行中服務鎖住，pip 會自動還原，記為「下次再試」，每天自動重試
            plan.append({"pkg": n, "cur": cur, "to": same[-1], "top": info.get("top") or [n.replace("-", "_").lower()],
                         "left": [x for x in cross if not (n.lower() in ("certifi", "tzdata"))], "bin": bool(info.get("bin"))})
        else:
            held.append({"pkg": n, "cur": cur, "fix": fixes[-1] if fixes else "", "why": "修補要跨大版本（可能不相容），需人工評估"})
    res = {"ts": now_s(), "patched": [], "failed": [], "rolled_back": [], "held": held, "plan": plan, "dry": dry}
    if dry or not plan:
        data["patch"] = res
        save(OUT, data)
        log("patch：計畫 %d、保留 %d（dry=%s）" % (len(plan), len(held), dry))
        return res
    os.makedirs(BACKUP_DIR, exist_ok=True)
    base_freeze = _freeze(py)
    bk = os.path.join(BACKUP_DIR, "freeze_%s.txt" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(bk, "w", encoding="utf-8") as f:
        f.write("\n".join("%s==%s" % kv for kv in sorted(base_freeze.items())))
    res["backup"] = bk
    base_check = _pip_check(py)
    # Lesson (2026-10-22): a plain `pip install` cascades dependency upgrades (Pillow 9→13, starlette 0.37→1.0 broke fastapi).
    # 改成「一次只換一個套件、--no-deps、換完 import 測試＋pip check 對照」，有新衝突就只退回那一個。
    for it in plan:
        before = _freeze(py)
        r = _pip(py, ["install", "--no-deps", "%s==%s" % (it["pkg"], it["to"])])
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", "replace")
            locked = bool(re.search(r"Access is denied|存取被拒|WinError 5|WinError 32|being used by another process", err, re.I))
            res["failed"].append({"pkg": it["pkg"], "to": it["to"], "locked": locked,
                                  "why": "檔案被執行中的服務鎖住，pip 已自動還原，下次再試" if locked else "安裝失敗", "err": err[-300:]})
            _restore(py, before)
            continue
        imp = "; ".join("import %s" % t for t in it["top"][:3] if re.match(r"^[A-Za-z_][\w\.]*$", t)) or "pass"
        t = subprocess.run([py, "-c", imp], capture_output=True, timeout=120, creationflags=CREATE_NO_WINDOW)
        newc = sorted(_pip_check(py) - base_check)
        if t.returncode != 0 or newc:
            _restore(py, before)
            res["rolled_back"].append({"pkg": it["pkg"], "to": it["to"],
                                       "why": ("升級後 import 失敗" if t.returncode != 0 else "升級後會和其他套件衝突：" + "；".join(newc)[:200]) + "，已退回 " + it["cur"]})
            continue
        res["patched"].append({"pkg": it["pkg"], "from": it["cur"], "to": it["to"], "left_cross_major": it["left"]})
    # 安全網：除了本輪成功修補的套件，任何版本變動都還原成備份
    after = _freeze(py)
    ok_pk = {x["pkg"].lower().replace("_", "-") for x in res["patched"]}
    stray = {k: v for k, v in base_freeze.items() if after.get(k) != v and k not in ok_pk}
    extra = [k for k in after if k not in base_freeze]
    if stray or extra:
        _pip(py, ["install", "--no-deps"] + ["%s==%s" % kv for kv in stray.items()])
        res["stray_restored"] = sorted(stray) + ["(新增)" + k for k in extra]
    res["pip_check_new"] = sorted(_pip_check(py) - base_check)
    data = load(OUT, {})
    data["patch"] = res
    save(OUT, data)
    log("patch：修好 %d、下次再試 %d、退回 %d、需評估 %d；最終新衝突 %d" % (len(res["patched"]), len(res["failed"]), len(res["rolled_back"]), len(held), len(res["pip_check_new"])))
    return res


def _pip(py, args, timeout=600):
    return subprocess.run([py, "-m", "pip"] + args + ["--disable-pip-version-check", "--no-input"], capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)


def _freeze(py):
    out = sh([py, "-m", "pip", "freeze", "--disable-pip-version-check"], 180)
    m = {}
    for l in out.splitlines():
        if "==" in l and not l.startswith("-e"):
            k, v = l.split("==", 1)
            m[k.strip().lower().replace("_", "-")] = v.strip()
    return m


def _restore(py, snap):
    cur = _freeze(py)
    diff = ["%s==%s" % (k, v) for k, v in snap.items() if cur.get(k) != v]
    if diff:
        _pip(py, ["install", "--no-deps"] + diff)


def main():
    a = sys.argv[1:] or ["run"]
    if a[0] == "show":
        print(json.dumps(load(OUT, {}).get("_meta"), ensure_ascii=False, indent=1))
        return
    if a[0] not in ("run", "patch"):
        print(__doc__)
        return
    lk = Lock("vuln_watch", timeout=0, stale=3 * 3600)
    if not lk.acquire():
        log("另一輪漏洞巡檢／修補還在跑，這次略過")
        print("busy")
        return
    try:
        if a[0] == "run":
            if "--patch" in a:
                before = load(OUT, {})
                run(notify=False)
                patch()
                run(notify="--no-notify" not in a, baseline=before)   # 修完重掃；只通知修不掉的新嚴重漏洞
            else:
                run(notify="--no-notify" not in a)
        else:
            patch(dry="--dry" in a)
    finally:
        lk.release()
    try:
        import shield_status
        shield_status.build()
    except Exception as e:
        log("總狀態更新失敗：%r" % e)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("崩潰：%r" % e)
        raise
