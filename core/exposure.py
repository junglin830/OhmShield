# -*- coding: utf-8 -*-
"""
OhmShield · 對外暴露分析：哪些套件「真的」被對外服務用到？
做法（保守，寧可多算不少算）：
  1. 靜態：從每個對外服務的進入點腳本出發，用 ast 掃所有 import（含函式內的延遲 import），
     同資料夾／子資料夾的本地模組會一路追下去；第三方的頂層模組名收集起來。
  2. 執行中：對外服務的行程目前已載入的 site-packages 編譯檔（.pyd/.dll）也算進去（Windows）。
  3. 用該直譯器的 importlib.metadata 把模組名對應回套件（distribution）名。
結果：{套件名(小寫): [哪些服務用到]}。vuln_watch 用它判斷漏洞是不是「對外」。
  python exposure.py           # 印出分析結果
MIT License.
"""
import os, sys, ast, json, re, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shield_common import CFG

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
STDLIB = set(getattr(sys, "stdlib_module_names", ()))


def _imports_of(path):
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(src, path)
    except Exception:
        return set(), set()
    mods, rel = set(), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                mods.add(a.name)
        elif isinstance(n, ast.ImportFrom):
            if n.level and n.level > 0:
                rel.add((n.module or "", n.level))
            elif n.module:
                mods.add(n.module)
        elif isinstance(n, ast.Call):   # importlib.import_module("x") / __import__("x")
            f = n.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name in ("import_module", "__import__") and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                mods.add(n.args[0].value)
    return mods, rel


def _local_file(mod, dirs):
    parts = mod.split(".")
    for d in dirs:
        p = os.path.join(d, *parts)
        if os.path.isfile(p + ".py"):
            return p + ".py"
        if os.path.isfile(os.path.join(p, "__init__.py")):
            return os.path.join(p, "__init__.py")
    return None


def static_closure(entry, extra_dirs=()):
    """回傳第三方頂層模組名集合"""
    base = os.path.dirname(os.path.abspath(entry))
    dirs = [base] + [d for d in extra_dirs if os.path.isdir(d)]
    seen, todo, third = set(), [os.path.abspath(entry)], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        mods, rel = _imports_of(f)
        for m in mods:
            top = m.split(".")[0]
            loc = _local_file(m, dirs + [os.path.dirname(f)]) or _local_file(top, dirs + [os.path.dirname(f)])
            if loc:
                todo.append(loc)
            elif top not in STDLIB and top not in ("__future__",):
                third.add(top)
        for m, lvl in rel:
            d = os.path.dirname(f)
            for _ in range(lvl - 1):
                d = os.path.dirname(d)
            loc = _local_file(m, [d]) if m else os.path.join(d, "__init__.py")
            if loc and os.path.isfile(loc):
                todo.append(loc)
    return third


def _pid_of_port(port):
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW).stdout.decode("utf-8", "replace")
    except Exception:
        return None
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 5 and cols[0] == "TCP" and cols[1].endswith(":%d" % port) and cols[3] in ("LISTENING", "接聽"):
            return int(cols[4])
    return None


def _module_paths(pid):
    """ctypes 讀行程已載入的 DLL/PYD 路徑（不開 PowerShell：排程的 pythonw 開 PS 會卡死）"""
    import ctypes
    from ctypes import wintypes
    k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    h = k32.OpenProcess(0x0410, False, pid)          # QUERY_INFORMATION | VM_READ
    if not h:
        return []
    try:
        arr = (wintypes.HMODULE * 4096)()
        need = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 3):
            return []
        n = min(need.value // ctypes.sizeof(wintypes.HMODULE), 4096)
        buf = ctypes.create_unicode_buffer(1024)
        out = []
        for i in range(n):
            if psapi.GetModuleFileNameExW(h, arr[i], buf, 1024):
                out.append(buf.value)
        return out
    finally:
        k32.CloseHandle(h)


def runtime_modules(ports):
    """Windows：對外服務行程已載入的 site-packages 編譯模組（頂層名）"""
    if os.name != "nt" or not ports:
        return {}
    out = {}
    for port in ports:
        pid = _pid_of_port(int(port))
        if not pid:
            continue
        names = set()
        for f in _module_paths(pid):
            if "site-packages" in f:
                top = f.split("site-packages\\", 1)[-1].split("\\")[0]
                if not top.startswith("_") and not re.match(r"^[0-9a-f]{10,}", top) and "." not in top:
                    names.add(top)
        out[str(port)] = names
    return out


def dist_map(py, modules):
    """用目標直譯器把頂層模組名對應到套件名，並展開「依賴的依賴」（requires，略過 extra 選配）"""
    code = r"""
import json,sys,re,importlib.metadata as m
pd=m.packages_distributions()
mods=json.loads(sys.argv[1])
def norm(n): return re.sub(r'[-_.]+','-',n).lower()
def deps(name,seen):
    k=norm(name)
    if k in seen: return
    seen.add(k)
    try: rq=m.requires(name) or []
    except Exception: return
    for r in rq:
        if 'extra ==' in r or 'extra==' in r: continue
        dn=re.split(r'[\s;<>=!~\[\(]',r.strip(),1)[0]
        if dn: deps(dn,seen)
out={}
for x in mods:
    s=set()
    for d in pd.get(x,[]): deps(d,s)
    out[x]=sorted(s)
print(json.dumps(out))
"""
    try:
        r = subprocess.run([py, "-c", code, json.dumps(sorted(modules))], capture_output=True, timeout=180, creationflags=CREATE_NO_WINDOW)
        return json.loads((r.stdout or b"{}").decode("utf-8", "replace").strip().splitlines()[-1])
    except Exception:
        return {}


def analyze():
    """設定 exposed_services: [{"name","entry","port","extra_dirs":[]}]。沒設定就回 None（全部視為對外，舊行為）"""
    services = CFG.get("exposed_services")
    if not services:
        return None
    py = CFG.get("exposed_python", sys.executable)
    per = {}
    allmods = set()
    for s in services:
        mods = static_closure(s["entry"], s.get("extra_dirs", [])) if os.path.exists(s.get("entry", "")) else set()
        per[s["name"]] = set(mods)
        allmods |= mods
    rt = runtime_modules([s["port"] for s in services if s.get("port")])
    for s in services:
        if s.get("port") and str(s["port"]) in rt:
            per[s["name"]] |= rt[str(s["port"])]
            allmods |= rt[str(s["port"])]
    dm = dist_map(py, allmods)
    used = {}
    for name, mods in per.items():
        for m in mods:
            for dist in dm.get(m, []) or []:
                used.setdefault(re.sub(r"[-_.]+", "-", dist).lower(), set()).add(name)
    return {k: sorted(v) for k, v in sorted(used.items())}


if __name__ == "__main__":
    r = analyze()
    print(json.dumps(r, ensure_ascii=False, indent=1) if r is not None else "未設定 exposed_services")
