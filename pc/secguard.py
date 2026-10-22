# -*- coding: utf-8 -*-
"""
OhmSecGuard — 只看不改的 Windows 個人電腦資安巡檢（Proxy／ClickFix／隱藏排程／根憑證／Defender 排除清單…）

一句話：每月完整「只讀」巡檢一次，加上「事件觸發快查」（網路重新連上、Defender 設定被改或抓到威脅時才跑，不輪詢），
跟「已知正常的基準線」比對；只有需要你動手的才跳 Windows 通知，同一問題只通知一次。

設計原則：
  - 預設不改任何設定。唯一的修改動作是 Proxy 還原/關閉，且必須你親手下指令，改前自動備份。
  - 基準線比對 + 已知攻擊手法特徵（ClickFix、Tarrask 隱藏排程、Defender 排除、MITM 根憑證、hosts 劫持、Proxy 死埠）。
  - 偵測到自己跑在 MSIX 封裝容器（例如被某些桌面 AI App 叫起來）時，會自動跳出容器重跑，避免讀到虛擬化的假登錄。

用法：
  python secguard.py scan [--print] [--no-notify]   完整巡檢
  python secguard.py quick [--print]                 事件快查（Proxy/hosts/瀏覽器政策/根憑證/Win+R/Defender 事件）
  python secguard.py accept <類別|all>               把某類目前狀態接受為新基準
  python secguard.py fix restore_proxy|disable_proxy 還原/關閉 Proxy（先備份）
  python secguard.py html                            產生 report.html
  python secguard.py rebaseline                      全部重建基準線
資料夾：與本檔同層的 secguard_data\
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

VERSION = '1.2.1'  # ClickFix 規則：要有執行器關鍵字(powershell/mshta/cmd /c…)，單純網址/檔案路徑不算
QUICK_CATS = ('proxy', 'winhttp', 'env_proxy', 'tool_proxy', 'hosts', 'browser', 'rootcert', 'clickfix', 'defevents', 'admin')
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'secguard_data')
COLLECT = os.path.join(HERE, 'collect.ps1')
CONFIG = os.path.join(HERE, 'config.json')
BASELINE = os.path.join(DATA, 'baseline.json')
REPORT = os.path.join(DATA, 'report.json')
EVENTS = os.path.join(DATA, 'events.jsonl')
NOTIFIED = os.path.join(DATA, 'notified.json')
ADMIN_FACTS = os.path.join(DATA, 'admin_facts.json')
BACKUPS = os.path.join(DATA, 'backups')
NOWIN = 0x08000000  # CREATE_NO_WINDOW

IOC_DOMAINS = []  # 由 config.json 的 hosts_must_block 提供（你在 hosts 封鎖過、必須一直封鎖的惡意網域）
SUSPICIOUS_ACT = [
    (r'(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}', '用編碼過的 PowerShell 指令（常見惡意手法）'),
    (r'(?i)(iex|invoke-expression)\b', 'PowerShell 直接執行下載內容（iex）'),
    (r'(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\s|curl\s|wget\s|bitsadmin)', '會從網路下載東西'),
    (r'(?i)add-mppreference|set-mppreference', '會改 Defender 防毒設定（排除清單）'),
    (r'(?i)\bmshta(\.exe)?\b', '用 mshta 執行（常見惡意手法）'),
    (r'(?i)rundll32(\.exe)?\s+[^,]*https?://', 'rundll32 載入網址'),
    (r'(?i)-w(indowstyle)?\s+h(idden)?\b.*https?://', '隱藏視窗並連網'),
    (r'(?i)\\system32\\[^\\]*versionagent', '與已知 ClickFix 惡意程式同名特徵（MicrosoftVersionAgent）'),
    (r'(?i)\bnode(\.exe)?\b.*\\(system32|programdata|temp)\\', 'node 從系統/暫存資料夾執行（已知竊密程式手法）'),
    (r'(?i)\\(appdata\\local\\temp|users\\public|programdata)\\[^"\s]+\.(exe|ps1|js|vbs|bat|cmd)', '從暫存/公用資料夾執行程式'),
]
OWN_HINTS = re.compile(r'(?i)(\\OhmSecGuard|OhmSecGuard|run_hidden\.vbs)')
CONN_ALERT = 800   # 單一行程 TCP 連線數（實際案例：惡意 node 開了約 6000 個）


# ------------------------------------------------------------------ io helpers
def _now():
    return time.strftime('%Y-%m-%d %H:%M:%S')


def _load(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _event(kind, **kw):
    os.makedirs(DATA, exist_ok=True)
    try:
        if os.path.exists(EVENTS) and os.path.getsize(EVENTS) > 3_000_000:
            os.replace(EVENTS, EVENTS + '.1')
        with open(EVENTS, 'a', encoding='utf-8') as f:
            f.write(json.dumps(dict(ts=_now(), kind=kind, **kw), ensure_ascii=False) + '\n')
    except Exception:
        pass


OWN_HINTS_DEFAULT = OWN_HINTS


def _clean(s):
    return (s or '').replace('\x00', '').strip()


def _fp(obj):
    return hashlib.sha1(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()[:12]


# ------------------------------------------------------------------ collect
def collect(quick=False):
    env = dict(os.environ)
    env.pop('PSModulePath', None)  # 從 pwsh 7 底下呼叫時，PS5 會吃到錯的模組路徑而找不到 cmdlet
    os.makedirs(DATA, exist_ok=True)
    out_path = os.path.join(DATA, 'collect_last.json')
    try:
        os.remove(out_path)
    except OSError:
        pass
    # 2026-10-22 實測（排程 pythonw 環境）：
    #   直接 Popen powershell + CREATE_NO_WINDOW → PS5 卡死在啟動；conhost --headless → 立刻結束沒跑。
    #   可行：交給 wscript _run_hidden.vbs（SW_HIDE），結果走檔案。
    subprocess.Popen(['wscript.exe', os.path.join(HERE, 'run_hidden.vbs'), 'powershell.exe', '-NoProfile', '-NonInteractive',
                      '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', COLLECT, '-Out', out_path] + (['-Quick'] if quick else []),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env)
    t_end = time.time() + 240   # conhost 不一定等子程式結束，所以等「結果檔」出現
    while time.time() < t_end and not os.path.exists(out_path):
        time.sleep(1)
    if not os.path.exists(out_path):
        raise RuntimeError('collector 240 秒內沒有產出結果（最後進度：%s）' % (open(os.path.join(DATA, 'collect_progress.txt'), encoding='utf-8', errors='replace').read() if os.path.exists(os.path.join(DATA, 'collect_progress.txt')) else '無'))
    with open(out_path, encoding='utf-8-sig') as f:
        d = json.load(f)
    for a in d.get('autostart') or []:
        a['cmd'] = _clean(a.get('cmd'))
    for t in d.get('tasks') or []:
        t['act'] = _clean(t.get('act'))
    return d


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ------------------------------------------------------------------ snapshot of comparable categories
def snapshot(d):
    pr = d.get('proxy') or {}
    return {
        'proxy': {k: pr.get(k, '') for k in ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')},
        'winhttp': d.get('winhttp') or 'direct',
        'env_proxy': d.get('env_proxy') or {},
        'tool_proxy': d.get('tool_proxy') or {},
        'hosts': sorted(_as_list((d.get('hosts') or {}).get('lines'))),
        'dns': sorted(['%s=%s' % (x.get('ifname'), ','.join(_as_list(x.get('servers')))) for x in _as_list(d.get('dns'))]),
        'firewall': d.get('firewall') or {},
        'tasks': sorted(t['key'] for t in _as_list(d.get('tasks'))),
        'autostart': sorted(a['key'] for a in _as_list(d.get('autostart'))),
        'browser': d.get('browser_policy') or {},
        'rootcert': sorted(_as_list(d.get('rootcerts'))),
        'clickfix': sorted(_as_list(d.get('runmru'))),
    }


CAT_NAME = {
    'proxy': 'Proxy（瀏覽器/系統代理）', 'winhttp': 'WinHTTP 系統代理', 'env_proxy': '環境變數 Proxy',
    'tool_proxy': 'git / npm / pip 的 Proxy', 'hosts': 'hosts 檔', 'dns': 'DNS 伺服器', 'firewall': '防火牆',
    'tasks': '排程工作', 'autostart': '開機自動啟動', 'browser': '瀏覽器政策（代理/強制擴充功能）',
    'rootcert': '受信任根憑證', 'clickfix': 'Win+R / 檔案總管網址列紀錄',
}
CLICKFIX = re.compile(r'(?i)(powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|rundll32|regsvr32|msiexec\s+/i\s*https?|\biex\b|invoke-(expression|webrequest|restmethod)|-enc(odedcommand)?\s|frombase64|\bcmd(\.exe)?\s+/c)')


def _diff(a, b):
    """return human readable list of changes from baseline a -> current b"""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                out.append('%s：%s → %s' % (k, a.get(k, '（無）') if a.get(k, '') != '' else '（空）', b.get(k, '（無）') if b.get(k, '') != '' else '（空）'))
    elif isinstance(a, list) and isinstance(b, list):
        sa, sb = set(a), set(b)
        out += ['新增：' + x for x in sorted(sb - sa)]
        out += ['移除：' + x for x in sorted(sa - sb)]
    else:
        out.append('%s → %s' % (a, b))
    return out


# ------------------------------------------------------------------ analysis
def analyse(d, base):
    F = []
    cfg = _cfg()
    ioc_domains = cfg.get('hosts_must_block', IOC_DOMAINS)
    own = re.compile(cfg['own_hints']) if cfg.get('own_hints') else OWN_HINTS

    def add(fid, cat, level, title, detail='', fix=None, notify=False, data=None, advice=''):
        F.append(dict(id=fid, cat=cat, level=level, title=title, detail=detail, advice=advice,
                      fix=fix, notify=notify, fp=_fp([fid, level, title, detail, data])))

    snap = snapshot(d)
    listen = set(int(x) for x in _as_list(d.get('listen')) if str(x).isdigit())

    # ---------- Proxy：最重要（不小心改到會整台斷網）
    pr = snap['proxy']
    if pr.get('ProxyEnable') == 1:
        m = re.search(r'(?:^|[=;])(?:https?://)?(127\.0\.0\.1|localhost|\[::1\]):(\d+)', pr.get('ProxyServer') or '')
        if m and int(m.group(2)) not in listen:
            add('proxy_dead', 'proxy', 'alert', 'Proxy 開著，但指向的本機程式沒在跑 → 瀏覽器/很多程式會連不上網',
                '目前代理：%s（埠 %s 沒有程式在聽）。常見原因：VPN／翻牆／抓包工具關掉時沒把系統代理還原。' % (pr.get('ProxyServer'), m.group(2)),
                fix='disable_proxy', notify=True,
                advice='執行 python secguard.py fix disable_proxy（會先備份），或重新打開原本那支代理工具。')
        elif not m and pr.get('ProxyServer'):
            add('proxy_remote', 'proxy', 'warn', '系統 Proxy 指向外部主機：' + pr.get('ProxyServer'),
                '所有網頁流量會先經過這台主機。如果不是你自己設的，流量可能被監看。', fix='restore_proxy', notify=True,
                advice='不是自己設的 → 按「還原 Proxy 到基準」。')
    if pr.get('AutoConfigURL'):
        add('proxy_pac', 'proxy', 'warn', '有設定自動代理腳本（PAC）：' + pr.get('AutoConfigURL'),
            'PAC 可以決定哪些網站走哪個代理，常被惡意程式用來攔截流量。', fix='restore_proxy', notify=True)
    if snap['winhttp'] != 'direct':
        add('winhttp', 'winhttp', 'warn', 'WinHTTP 系統代理不是直連', d.get('winhttp') or '', notify=True,
            advice='Windows Update、很多背景服務會走這個設定；不是自己設的要處理（需管理員）。')

    # ---------- 與基準線比對（任何變化都記錄；Proxy 類變化一律通知）
    if base:
        bsnap = base.get('snap') or {}
        for cat in ('proxy', 'winhttp', 'env_proxy', 'tool_proxy', 'hosts', 'dns', 'firewall', 'tasks', 'autostart', 'browser', 'rootcert'):
            failed = any(e.startswith(cat.split('_')[0] + ':') or e.startswith(cat + ':') or e.startswith(cat + 's:') for e in _as_list(d.get('errors')))
            if failed or (d.get('quick') and cat not in QUICK_CATS):
                continue
            if cat not in bsnap:
                continue  # 新增類別：第一次只建基準，不報差異
            if cat in bsnap and bsnap[cat] != snap[cat]:
                ch = _diff(bsnap[cat], snap[cat])
                if not ch:
                    continue
                net = cat in ('proxy', 'winhttp', 'env_proxy', 'tool_proxy', 'dns', 'hosts')
                if cat == 'rootcert':
                    added = [x[3:] for x in ch if x.startswith('新增：')]
                    lvl = 'alert' if any(x.startswith('CurrentUser|') for x in added) else ('warn' if added else 'info')
                    note = '（可能被裝了中間人憑證，可偷看 HTTPS）' if added else ''
                elif cat in ('tasks', 'autostart'):
                    added = [x[3:] for x in ch if x.startswith('新增：')]
                    is_own = all(own.search(x) for x in added) if added else True
                    lvl = 'info' if is_own else 'warn'
                    note = '（全部是白名單內的自家程式）' if is_own and added else ''
                else:
                    lvl = 'warn'
                    note = ''
                add('changed_' + cat, cat, lvl, '%s 跟基準線不一樣%s' % (CAT_NAME[cat], note), '\n'.join(ch[:30]),
                    fix='restore_proxy' if cat == 'proxy' else None, notify=(lvl != 'info'), data=ch,
                    advice='是自己改的 → 按「接受為新基準」；不是 → %s' % ('按「還原 Proxy 到基準」' if cat == 'proxy' else '看下方說明處理'))

    # ---------- hosts 內容檢查
    hl = snap['hosts']
    for dom in (ioc_domains if (d.get('hosts') or {}).get('sha256') else []):
        if not any(re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+' + re.escape(dom) + r'\b', x) for x in hl):
            add('ioc_hosts_' + dom, 'hosts', 'alert', '已封鎖的惡意網站封鎖消失：' + dom,
                'hosts 檔裡原本把這個網站封到 0.0.0.0，現在不見了 → 可能有東西改回去。', notify=True)
    for x in hl:
        parts = x.split()
        if len(parts) >= 2 and parts[0] not in ('0.0.0.0', '127.0.0.1', '::1', '::'):
            add('hosts_redirect_' + parts[1], 'hosts', 'alert', 'hosts 把網站導到其他 IP：' + x,
                '實際案例：惡意程式把 hosts 改成指向自己的伺服器。', notify=True)

    # ---------- 排程工作可疑內容
    for t in _as_list(d.get('tasks')):
        act = t.get('act') or ''
        if own.search(act) or own.search(t.get('key', '')):
            continue
        for pat, why in SUSPICIOUS_ACT:
            if re.search(pat, act):
                lvl = 'alert' if (t.get('state') != 'Disabled') else 'warn'
                add('task_sus_' + t['key'], 'tasks', lvl, '可疑排程：' + t['key'], '%s\n動作：%s\n作者：%s　建立：%s　狀態：%s' % (
                    why, act[:400], t.get('author') or '?', t.get('date') or '?', t.get('state')), notify=True,
                    advice='確認不是自己裝的軟體 → 停用、備份後刪除。')
                break
    for a in _as_list(d.get('autostart')):
        cmd = a.get('cmd') or ''
        if own.search(cmd):
            continue
        for pat, why in SUSPICIOUS_ACT:
            if re.search(pat, cmd):
                add('auto_sus_' + a['key'], 'autostart', 'alert', '可疑開機啟動：' + a['key'], why + '\n' + cmd[:400], notify=True)
                break

    # ---------- v1.2.0 ClickFix：Win+R / 檔案總管網址列 被貼過可疑指令
    seen_ok = set(_as_list(((base or {}).get('snap') or {}).get('clickfix')))
    for x in _as_list(d.get('runmru')):
        cmd = x.split('|', 1)[-1]
        if x in seen_ok:
            continue
        if CLICKFIX.search(cmd) and not own.search(cmd.replace('/', '\\')):
            add('clickfix_' + _fp(x), 'clickfix', 'alert', 'Win+R 執行過可疑指令（ClickFix「貼上指令驗證」手法）',
                cmd[:400] + '\n這是網頁騙人按 Win+R 貼上執行的典型手法。', notify=True,
                advice='不是你自己打的 → 立刻斷網排查、改密碼；是你自己的 → python secguard.py accept clickfix。')
    # ---------- v1.2.0 瀏覽器政策：被設定代理或強制安裝擴充功能（惡意程式常用）
    bp = d.get('browser_policy') or {}
    for k, v in bp.items():
        if k in (((base or {}).get('snap') or {}).get('browser') or {}):
            continue
        if re.search(r'Proxy', k):
            add('browser_proxy_' + k, 'browser', 'alert', '瀏覽器被政策強制設定代理：' + k, str(v)[:300], notify=True,
                advice='不是你設的 → 流量可能被攔截，移除該瀏覽器政策。')
        elif 'ForceExt' in k:
            add('browser_ext_' + k, 'browser', 'warn', '瀏覽器被強制安裝擴充功能：' + str(v)[:120], k, notify=True,
                advice='強制安裝的擴充功能使用者無法移除，常被用來偷 cookie/密碼。')
    # ---------- v1.2.0 Defender 設定被改／抓到威脅（事件紀錄，近 35 天、在「已確認」之後）
    ack = ((base or {}).get('ack') or {}).get('defevents') or (base or {}).get('created') or ''
    for ev in _as_list(d.get('def_events')):
        if str(ev.get('time', '')) <= ack:
            continue
        eid = ev.get('id')
        if eid == 5007:
            ttl, lvl = 'Defender 設定被修改（排除清單／關閉防護）', 'alert'
        elif eid in (5001, 5010, 5012):
            ttl, lvl = 'Defender 防護被關閉（事件 %s）' % eid, 'alert'
        else:
            ttl, lvl = 'Defender 抓到威脅（事件 %s）' % eid, 'alert'
        add('defev_%s' % ev.get('rec'), 'defevents', lvl, '%s　%s' % (ttl, ev.get('time')), ev.get('msg', ''), notify=True,
            advice='竊密程式常見第一步就是把自己加進 Defender 排除清單。不是你改的 → 立即排查；確認沒事 → python secguard.py accept defevents。')

    # ---------- v1.2.1 Defender 被群組原則關閉（惡意程式常寫 Policies\Windows Defender 的 Disable* 值）
    for k, v in (d.get('def_policy') or {}).items():
        name = k.split('\\')[-1]
        if re.match(r'(?i)^(Disable\w*|DisableAntiSpyware|DisableAntiVirus)$', name) and str(v).strip() == '1':
            add('defpol_' + name, 'defender', 'alert', 'Defender 被群組原則關閉：' + name + ' = 1',
                '登錄位置 HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' + k.rsplit('\\', 1)[0] +
                '\n目前若「竄改防護」開著會被忽略；一旦竄改防護被關，這個設定就會讓防毒失效。家用電腦正常不會有這個值。', notify=True,
                advice='確認不是公司/學校管理的電腦 → 以系統管理員刪除這個原則值（先匯出備份）。')
        elif re.search(r'(?i)SubmitSamplesConsent|SpynetReporting', name) and str(v).strip() in ('0', '2'):
            add('defpol_' + name, 'defender', 'warn', 'Defender 雲端保護/樣本提交被原則降低：%s = %s' % (name, v), k, notify=False)

    # ---------- 已知 IOC
    for p in _as_list(d.get('ioc')):
        add('ioc_dir', 'ioc', 'alert', '已知惡意程式資料夾出現', p + '\n代表還有其他入口，要重新排查。', notify=True)

    # ---------- 異常連線數
    for c in _as_list(d.get('conn_top')):
        if c.get('pid') and c.get('count', 0) >= CONN_ALERT:
            add('conn_%s' % (c.get('name') or c.get('pid')), 'network', 'alert',
                '%s 開了 %s 條連線（異常大量）' % (c.get('name'), c.get('count')),
                '路徑：%s　PID %s。實際案例：惡意 node 開了約 6000 條。' % (c.get('path') or '（無權限讀取，可能是管理員行程）', c.get('pid')), notify=True)

    # ---------- 動態埠
    dp = d.get('dynport') or {}
    if dp and dp.get('start') and (dp.get('start') != 49152 or dp.get('num') != 16384):
        add('dynport', 'network', 'warn', '臨時連接埠範圍被改了：從 %s 開始共 %s 個' % (dp.get('start'), dp.get('num')),
            '10/22 已修為 49152 起 16384 個；被改回小範圍會跟本機服務搶埠。', notify=True)

    # ---------- Defender / UAC / 防火牆 / RDP
    df = d.get('defender') or {}
    if df:
        if not df.get('rtp') or not df.get('av'):
            add('def_off', 'defender', 'alert', 'Defender 即時防護被關掉了', json.dumps(df, ensure_ascii=False), notify=True)
        if df.get('sig_age', 0) > 3:
            add('def_sig', 'defender', 'warn', 'Defender 病毒碼 %s 天沒更新' % df.get('sig_age'), '', notify=False)
        if df.get('full_age', 0) > 30 and df.get('quick_age', 0) > 7:
            add('def_scan', 'defender', 'info', 'Defender 很久沒掃描（快速 %s 天／完整 %s 天）' % (df.get('quick_age'), df.get('full_age')))
    for th in _as_list(d.get('threats')):
        add('threat_' + str(th.get('id')), 'defender', 'alert', 'Defender 近 7 天抓到威脅（%s）' % th.get('time'), th.get('res', '')[:400], notify=True)
    if d.get('uac') == 0:
        add('uac_off', 'system', 'alert', 'UAC（使用者帳戶控制）被關掉了', '任何程式都能直接拿到管理員權限。', notify=True)
    fw = d.get('firewall') or {}
    if fw and not any(fw.values()):
        add('fw_off', 'firewall', 'warn', 'Windows 防火牆三個設定檔全部關閉',
            '目前 Domain/Private/Public 都是關的。開啟前先確認你的區網服務會不會被擋；本工具只提醒、不自動開。', notify=False,
            advice='先列出需要放行的埠，再開啟防火牆。')
    if d.get('rdp_deny') == 0:
        add('rdp_on', 'system', 'info', '遠端桌面（RDP）是開啟的', '沒在用的話建議關掉。')

    errs = _as_list(d.get('errors'))
    if errs:
        add('collector_err', 'system', 'info', '有 %d 項資料這輪沒讀到（下一輪會再試）' % len(errs), '\n'.join(e[:200] for e in errs))

    # ---------- 管理員輔助（Defender 排除清單、隱藏排程）
    af = _load(ADMIN_FACTS, None)
    if af:
        for ex in _as_list(af.get('excl_path')) + _as_list(af.get('excl_process')) + _as_list(af.get('excl_ext')):
            ex = _clean(str(ex))
            if not ex:
                continue
            exists = os.path.exists(ex) if re.match(r'^[A-Za-z]:\\', ex) else None
            danger = re.search(r'(?i)^(c:\\windows(\\system32)?\\?|c:\\|powershell(\.exe)?|cmd(\.exe)?|node(\.exe)?|\.exe|\.ps1|\.js)$', ex)
            lvl = 'alert' if danger else 'warn'
            add('excl_' + ex, 'admin', lvl, 'Defender 排除清單：' + ex,
                ('這個路徑已經不存在。' if exists is False else '') + ('這種排除等於讓防毒對大範圍失明。' if danger else '確認是自己加的；不需要就移除。'),
                notify=bool(danger))
        for t in _as_list(af.get('hidden_tasks')):
            add('hidden_task_' + str(t), 'admin', 'alert', '隱藏排程（安全描述被刪，工作排程器看不到）：' + str(t),
                'Tarrask 等惡意程式的隱藏手法：排程照跑但清單裡看不到。', notify=True, advice='用管理員權限查它跑什麼（HiddenTaskHunter 等工具）並隔離。')
        for w in _as_list(af.get('wmi_persist')):
            if re.search(r'(?i)SCM Event Log Consumer|BVTConsumer', str(w)):
                continue
            add('wmi_' + _fp(w), 'admin', 'alert', 'WMI 事件訂閱常駐（無檔案型後門常用）', str(w)[:400], notify=True)
        sh = _as_list(af.get('shadows'))
        if len(sh) >= 4:
            add('shadows', 'admin', 'warn', '近 35 天建立了 %d 個磁碟陰影複製' % len(sh), '、'.join(sh[-12:]) +
                '\n實際案例：竊密程式每 1～2 天建一次陰影複製來偷被鎖住的瀏覽器密碼/cookie；若不是系統還原點造成的要查。', notify=True)
    else:
        add('admin_helper', 'system', 'info', '管理員輔助還沒裝（看不到 Defender 排除清單）',
            '以系統管理員執行 install_admin_ADMIN.ps1 一次 → 之後每月由 SYSTEM 只讀抓排除清單/隱藏排程/WMI/陰影複製。')

    return F, snap


# ------------------------------------------------------------------ extras shown on page
def extras():
    return {}


# ------------------------------------------------------------------ notify (deduped by fingerprint)
def _cfg():
    return _load(CONFIG, {})


def _toast(title, body):
    """Windows 原生通知（不需安裝模組）。config.json 的 notify 可設 "none" 關閉，或設成自訂指令（{title}/{body} 會被替換）。"""
    mode = _cfg().get('notify', 'toast')
    if mode == 'none':
        return
    if mode != 'toast':
        subprocess.Popen(mode.replace('{title}', title).replace('{body}', body), shell=True, creationflags=NOWIN)
        return
    esc = lambda t: (t or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace("'", "''")
    ps = ("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
          "$x = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]::new();"
          "$x.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>%s</text><text>%s</text></binding></visual></toast>');"
          "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Windows PowerShell').Show([Windows.UI.Notifications.ToastNotification]::new($x))"
          % (esc(title), esc(body)))
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps], capture_output=True, timeout=60, creationflags=NOWIN)


def _notify(findings):
    sent = []
    state = _load(NOTIFIED, {})
    live = {f['id'] for f in findings}
    for f in findings:
        if not f.get('notify') or f['level'] not in ('warn', 'alert'):
            continue
        if state.get(f['id']) == f['fp']:
            continue
        try:
            _toast('電腦資安：' + f['title'], ((f.get('detail') or '').split('\n')[0][:160]) + (('\n建議：' + f['advice']) if f.get('advice') else ''))
            state[f['id']] = f['fp']
            sent.append(f['id'])
        except Exception as e:
            _event('notify_error', id=f['id'], err=repr(e))
    # 問題消失 → 清掉狀態（之後再出現會再通知一次）
    for k in list(state):
        if k not in live:
            state.pop(k)
    _save(NOTIFIED, state)
    return sent


# ------------------------------------------------------------------ main ops
def _extend_baseline(base, snap, d):
    """新版本新增的類別（瀏覽器政策、根憑證）第一次看到時直接記為基準；clickfix 例外（要你確認才算正常）。"""
    errs = ' '.join(_as_list(d.get('errors')))
    added = []
    for cat in ('browser', 'rootcert'):
        if cat not in base.get('snap', {}) and cat in snap and (cat + ':') not in errs and (cat + 's:') not in errs:
            base['snap'][cat] = snap[cat]
            added.append(cat)
    if added:
        base['updated'] = _now()
        _save(BASELINE, base)
        _event('baseline_extended', cats=added)


def _packaged():
    """是否跑在 Claude 桌面版等 MSIX 封裝容器裡（HKCU/AppData 被虛擬化，讀到的不是真的）。"""
    try:
        import ctypes
        n = ctypes.c_uint32(0)
        rc = ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(n), None)
        if rc != 15700:  # APPMODEL_ERROR_NO_PACKAGE → 本身有封裝身分
            return True
    except Exception:
        pass
    # 2026-10-22 實測：Claude 桌面版底下開的子孫程式沒有封裝身分，但 HKCU/AppData 照樣被虛擬化 → 看祖先有沒有 WindowsApps 裡的程式
    try:
        import psutil
        p = psutil.Process().parent()
        for _ in range(12):
            if p is None:
                break
            exe = (p.exe() or '').lower()
            if '\\windowsapps\\' in exe:
                return True
            p = p.parent()
    except Exception:
        pass
    return False


def _escape_and_rerun(argv):
    """在封裝容器裡被叫到時，自動改用 WMI 在容器外重跑同一指令（避免讀到假的登錄、把基準線弄髒）。"""
    out = os.path.join(DATA, 'escaped_%d.txt' % os.getpid())
    py = sys.executable.replace('pythonw.exe', 'python.exe')
    cmdline = 'conhost.exe --headless cmd.exe /c "set PYTHONIOENCODING=utf-8&& "%s" "%s" %s --escaped > "%s" 2>&1 & echo __SECGUARD_DONE__>> "%s""' % (
        py, os.path.abspath(__file__), ' '.join(argv[1:]), out, out)
    ps = "$r = Invoke-CimMethod Win32_Process -MethodName Create -Arguments @{CommandLine='%s'; CurrentDirectory='%s'}; $r.ProcessId" % (
        cmdline.replace("'", "''"), HERE)
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps], capture_output=True, timeout=60, creationflags=NOWIN)
    t_end = time.time() + 300
    txt = ''
    while time.time() < t_end:
        time.sleep(2)
        try:
            txt = open(out, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        if '__SECGUARD_DONE__' in txt:
            break
    try:
        os.remove(out)
    except OSError:
        pass
    txt = txt.replace('__SECGUARD_DONE__', '').rstrip() + '\n'
    sys.stdout.write(txt)
    return 0


def _escaped_running(out):
    try:
        p = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                            "(Get-CimInstance Win32_Process -Filter \"Name='cmd.exe'\" | Where-Object { $_.CommandLine -like '*%s*' }).Count" % os.path.basename(out)],
                           capture_output=True, timeout=30, creationflags=NOWIN)
        return (p.stdout.decode(errors='replace').strip() or '0') != '0'
    except Exception:
        return False


def scan(do_notify=True):
    os.makedirs(DATA, exist_ok=True)
    t0 = time.time()
    d = collect()
    base = _load(BASELINE, None)
    findings, snap = analyse(d, base)
    if not base:
        base = dict(created=_now(), updated=_now(), snap=snap, note='第一次巡檢自動建立；之後可逐類 accept 接受為新基準')
        _save(BASELINE, base)
        _event('baseline_created')
    else:
        _extend_baseline(base, snap, d)
    order = {'alert': 0, 'warn': 1, 'info': 2, 'ok': 3}
    findings.sort(key=lambda f: (order.get(f['level'], 9), f['cat']))
    sent = _notify(findings) if do_notify else []
    counts = {k: sum(1 for f in findings if f['level'] == k) for k in ('alert', 'warn', 'info')}
    score = max(0, 100 - counts['alert'] * 25 - counts['warn'] * 8 - counts['info'] * 1)
    prev = _load(REPORT, {})
    rep = dict(version=VERSION, ts=_now(), took=round(time.time() - t0, 1), score=score, counts=counts, findings=findings,
               raw=dict(proxy=d.get('proxy'), winhttp=d.get('winhttp'), env_proxy=d.get('env_proxy'), tool_proxy=d.get('tool_proxy'),
                        dns=d.get('dns'), firewall=d.get('firewall'), defender=d.get('defender'), dynport=d.get('dynport'),
                        hosts=(d.get('hosts') or {}), conn_top=d.get('conn_top'), uac=d.get('uac'), rdp_deny=d.get('rdp_deny'),
                        tasks_n=len(_as_list(d.get('tasks'))), timing=d.get('timing'),
                        browser_policy=d.get('browser_policy'), def_policy=d.get('def_policy'), rootcerts_n=len(_as_list(d.get('rootcerts'))),
                        runmru_n=len(_as_list(d.get('runmru'))), def_events_n=len(_as_list(d.get('def_events'))),
                        admin=_load(ADMIN_FACTS, None), autostart=d.get('autostart'), errors=d.get('errors')),
               baseline=dict(created=base.get('created'), updated=base.get('updated'), accepted=base.get('accepted', {})),
               admin_helper=os.path.exists(ADMIN_FACTS), extras=extras(), notified=sent)
    _save(REPORT, rep)
    if [f['id'] for f in prev.get('findings', [])] != [f['id'] for f in findings]:
        _event('findings_changed', counts=counts, ids=[f['id'] for f in findings if f['level'] != 'info'])
    return rep


def quick_scan():
    """網路重新連線時跑：只查 Proxy/WinHTTP/環境變數/工具代理/hosts（約 3 秒），結果併進 report.json。"""
    os.makedirs(DATA, exist_ok=True)
    t0 = time.time()
    d = collect(quick=True)
    base = _load(BASELINE, None)
    if not base:
        return scan()
    fq, _ = analyse(d, base)
    fq = [f for f in fq if f['cat'] in QUICK_CATS]
    rep = _load(REPORT, None)
    if not rep:
        return scan()
    keep = [f for f in rep.get('findings', []) if f['cat'] not in QUICK_CATS]
    allf = fq + keep
    order = {'alert': 0, 'warn': 1, 'info': 2, 'ok': 3}
    allf.sort(key=lambda f: (order.get(f['level'], 9), f['cat']))
    sent = _notify(allf)
    counts = {k: sum(1 for f in allf if f['level'] == k) for k in ('alert', 'warn', 'info')}
    rep.update(findings=allf, counts=counts, score=max(0, 100 - counts['alert'] * 25 - counts['warn'] * 8 - counts['info']),
               quick_ts=_now(), quick_took=round(time.time() - t0, 1), notified=sent)
    for k in ('proxy', 'winhttp', 'env_proxy', 'tool_proxy', 'hosts', 'browser_policy', 'rootcerts', 'runmru', 'def_events'):
        if d.get(k) is not None:
            rep.setdefault('raw', {})[k] = d.get(k)
    _save(REPORT, rep)
    _event('quick', counts=counts)
    return rep


def accept(cat):
    base = _load(BASELINE, None)
    d = collect()
    snap = snapshot(d)
    if not base:
        base = dict(created=_now(), snap={})
    if cat == 'defevents':
        base.setdefault('ack', {})['defevents'] = _now()
    elif cat == 'all':
        base['snap'] = snap
        base.setdefault('ack', {})['defevents'] = _now()
    else:
        if cat not in snap:
            raise ValueError('未知類別：' + cat)
        base['snap'][cat] = snap[cat]
    base['updated'] = _now()
    base.setdefault('accepted', {})[cat] = _now()
    _save(BASELINE, base)
    _event('accept', cat=cat)
    return dict(ok=True, cat=cat)


def _refresh_wininet():
    try:
        import ctypes
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        w.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def fix(action):
    """只在你親手下指令時執行。改前先備份到 secguard_data\\backups\\。"""
    import winreg
    KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    names = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')
    os.makedirs(BACKUPS, exist_ok=True)
    cur = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_READ) as k:
        for n in names:
            try:
                cur[n] = winreg.QueryValueEx(k, n)
            except FileNotFoundError:
                cur[n] = None
    bk = os.path.join(BACKUPS, 'proxy_%s.json' % time.strftime('%Y%m%d_%H%M%S'))
    _save(bk, {n: (list(v) if v else None) for n, v in cur.items()})
    if action == 'disable_proxy':
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
    elif action == 'restore_proxy':
        base = _load(BASELINE, None)
        bp = ((base or {}).get('snap') or {}).get('proxy')
        if not bp:
            raise ValueError('沒有 Proxy 基準線可還原')
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, 'ProxyEnable', 0, winreg.REG_DWORD, int(bp.get('ProxyEnable') or 0))
            for n in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL'):
                v = bp.get(n) or ''
                if v:
                    winreg.SetValueEx(k, n, 0, winreg.REG_SZ, v)
                else:
                    try:
                        winreg.DeleteValue(k, n)
                    except FileNotFoundError:
                        pass
    else:
        raise ValueError('未知修復動作：' + action)
    _refresh_wininet()
    _event('fix', action=action, backup=bk)
    return dict(ok=True, action=action, backup=bk)


def write_html():
    """把 report.json 轉成一頁可直接開的 report.html（不需伺服器）。"""
    import html as H
    r = _load(REPORT, None) or scan(do_notify=False)
    col = {'alert': '#ef7d7d', 'warn': '#e7b96a', 'info': '#8db6d6'}
    rows = ''.join('<div class="f" style="border-left-color:%s"><b>[%s] %s</b><pre>%s</pre>%s</div>' % (
        col.get(f['level'], '#888'), f['level'].upper(), H.escape(f['title']), H.escape(f.get('detail') or ''),
        ('<p class="a">→ %s</p>' % H.escape(f['advice'])) if f.get('advice') else '') for f in r.get('findings', [])) or '<p class="ok">✓ 沒有任何發現</p>'
    page = ('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OhmSecGuard report</title>'
            '<style>body{margin:0;background:#0b0d12;color:#ece7dc;font:14px/1.6 system-ui,"Noto Sans TC",sans-serif}main{max-width:900px;margin:auto;padding:24px 16px}'
            'h1{font-weight:600}.s{font-size:44px;color:#d5bd8c}.f{background:#141823;border-left:4px solid;border-radius:10px;padding:12px 16px;margin:10px 0}'
            'pre{white-space:pre-wrap;color:#a9a59c;margin:6px 0 0;font:12px/1.5 Consolas,monospace}.a{color:#d5bd8c;margin:6px 0 0}.ok{color:#8fc8b2}</style>'
            '<main><h1>OhmSecGuard <small style="color:#a9a59c;font-size:14px">%s · v%s</small></h1><div class="s">%s</div>%s</main>') % (
        H.escape(r.get('ts', '')), H.escape(r.get('version', '')), r.get('score', ''), rows)
    out = os.path.join(DATA, 'report.html')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(page)
    return out


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'scan'
    if cmd in ('scan', 'quick', 'accept', 'fix', 'rebaseline') and '--escaped' not in argv and _packaged():
        return _escape_and_rerun(argv)
    argv = [a for a in argv if a != '--escaped']
    if cmd == 'scan':
        r = scan(do_notify='--no-notify' not in argv)
        if '--print' in argv:
            print('score', r['score'], r['counts'], 'took', r['took'], 's', 'notified', r['notified'])
            for f in r['findings']:
                print('[%s] %s | %s' % (f['level'], f['id'], f['title']))
    elif cmd == 'quick':
        r = quick_scan()
        if '--print' in argv:
            print('quick', r.get('quick_ts'), r['counts'], [f['id'] for f in r['findings']])
    elif cmd == 'accept':
        print(json.dumps(accept(argv[2]), ensure_ascii=False))
    elif cmd == 'fix':
        print(json.dumps(fix(argv[2]), ensure_ascii=False))
    elif cmd == 'html':
        print(write_html())
    elif cmd == 'rebaseline':
        print(json.dumps(accept('all'), ensure_ascii=False))
    else:
        print(__doc__)


if __name__ == '__main__':
    import faulthandler
    os.makedirs(DATA, exist_ok=True)
    _hang_log = open(os.path.join(DATA, 'hang_trace.txt'), 'w', encoding='utf-8')
    faulthandler.dump_traceback_later(int(os.environ.get('SECGUARD_HANG_SEC') or 200), exit=False, file=_hang_log)  # 卡住時自動留下堆疊
    try:
        main(sys.argv)
    except Exception as e:
        _event('error', err=repr(e))
        raise
