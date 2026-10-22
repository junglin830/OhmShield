# -*- coding: utf-8 -*-
"""
OhmShield · IP Intel — 自架網站的「訪客 IP 身分辨識＋惡意掃描自動封鎖」引擎
Identify every IP that hits your self-hosted web server, write a human-readable note for
each one, and auto-block vulnerability scanners.

  python ip_intel.py run                 # incremental (new IPs only) — run hourly via cron / Task Scheduler
  python ip_intel.py run --dry           # print verdicts, write nothing
  python ip_intel.py recheck [--max N]   # re-lookup every IP
  python ip_intel.py recheck-empty       # re-lookup IPs whose network owner is still unknown
  python ip_intel.py show <ip>
  python ip_intel.py block <ip> [備註] | unblock <ip>

Config: config.json next to this file (see config.example.json) or env OGS_CONFIG=<path>.
Input log: JSON Lines (one object per request: {"t":"MM-DD HH:MM:SS","ip","cty","p","q","ref","ua"})
or nginx/Apache "combined" format ("log_format": "combined").
Blocklist output: {ip: {blocked_at, reason, note}} — have your server deny IPs in this file.
Standard library only. MIT License.
"""
import sys, os, json, re, time, socket, ipaddress, datetime, urllib.request, urllib.error, collections, threading

VERSION = "1.2.0"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shield_common import CFG, Lock, block_ip, unblock_ip, valid_ip   # 設定、鎖、封鎖清單（兩個入口共用）
VISITLOG = CFG["visit_log"]
LOG_FORMAT = CFG.get("log_format", "jsonl")          # jsonl | combined
BLOCKLIST = CFG["blocklist"]
NOTES = CFG["ip_notes"]
LOG = CFG.get("engine_log") or os.path.join(CFG["_dir"], "ip_intel.log")
AUTO_BLOCK = CFG.get("auto_block", True)
OWNER = CFG.get("owner_label", "站長")
RECHECK_DAYS = int(CFG.get("recheck_days", 7))
MAX_LOOKUPS = int(CFG.get("max_lookups", 80))
RECHECK_EMPTY = False
UA = "OhmShield-IpIntel/1.1 (+https://github.com/junglin830/OhmShield)"
_SELF = CFG.get("self_ua_markers", ["ohm-health", "uptime-kuma", "UptimeRobot"])     # 你自己的監控 UA：其 IP 視為自家、永不封
_ADMIN = CFG.get("owner_paths_regex", r"^/admin\b|^/dashboard\b|^/api/(blocklist|block|unblock)")  # 只有站長能開的路徑
COUNTRY_HOME = CFG.get("home_country", "TW")

SELF_UA = re.compile("|".join(re.escape(x) for x in _SELF) or r"$^", re.I)
# 平台「連結預覽」機器人：有人在該平台分享了網址，平台伺服器來抓縮圖/標題
PLATFORM_UA = [
    (re.compile(r"line-poker", re.I), "LINE 連結預覽"),
    (re.compile(r"facebookexternalhit|facebookcatalog|meta-externalagent", re.I), "Facebook／Messenger／IG 連結預覽"),
    (re.compile(r"Twitterbot", re.I), "X(Twitter) 連結預覽"),
    (re.compile(r"TelegramBot", re.I), "Telegram 連結預覽"),
    (re.compile(r"Discordbot", re.I), "Discord 連結預覽"),
    (re.compile(r"Slackbot", re.I), "Slack 連結預覽"),
    (re.compile(r"WhatsApp", re.I), "WhatsApp 連結預覽"),
    (re.compile(r"SkypeUriPreview", re.I), "Skype／Teams 連結預覽"),
    (re.compile(r"LinkedInBot", re.I), "LinkedIn 連結預覽"),
    (re.compile(r"Pinterest", re.I), "Pinterest 連結預覽"),
    (re.compile(r"Iframely|Embedly", re.I), "嵌入預覽服務"),
]
SEARCH_UA = [
    (re.compile(r"Googlebot|Google-InspectionTool|GoogleOther|AdsBot-Google|Google-Read-Aloud|Storebot-Google", re.I), "Google 搜尋爬蟲"),
    (re.compile(r"bingbot|BingPreview|msnbot", re.I), "Bing 搜尋爬蟲"),
    (re.compile(r"Applebot", re.I), "Apple 搜尋爬蟲"),
    (re.compile(r"YandexBot|YandexImages", re.I), "Yandex 搜尋爬蟲"),
    (re.compile(r"Baiduspider", re.I), "百度爬蟲"),
    (re.compile(r"DuckDuckBot", re.I), "DuckDuckGo 爬蟲"),
    (re.compile(r"PetalBot", re.I), "華為 Petal 爬蟲"),
    (re.compile(r"GPTBot|ChatGPT-User|OAI-SearchBot", re.I), "OpenAI 爬蟲"),
    (re.compile(r"ClaudeBot|Claude-User|anthropic-ai", re.I), "Anthropic 爬蟲"),
    (re.compile(r"PerplexityBot", re.I), "Perplexity 爬蟲"),
    (re.compile(r"CCBot", re.I), "Common Crawl 爬蟲"),
    (re.compile(r"AhrefsBot|SemrushBot|MJ12bot|DotBot|DataForSeoBot|BLEXBot|SeznamBot|Bytespider|Amazonbot", re.I), "SEO／資料蒐集爬蟲"),
]
TOOL_UA = re.compile(r"^(curl|wget|python-requests|python-urllib|aiohttp|Go-http-client|okhttp|Java/|libwww|httpx|node-fetch|axios|undici|Wget|PostmanRuntime)|zgrab|masscan|nmap|Nuclei|sqlmap|nikto|WPScan|CensysInspect|Expanse|Palo Alto|internet-measurement|l9scan|ModatScanner|Odin|InternetMeasurement|Shodan", re.I)
SCANNER_UA = re.compile(r"zgrab|masscan|nmap|Nuclei|sqlmap|nikto|WPScan|CensysInspect|Expanse|internet-measurement|l9scan|ModatScanner|Shodan|InternetMeasurement|Odin", re.I)
# 掃描/攻擊路徑：正常訪客不會打這些（注意：/admin 是站長入口，不算）
SCAN_P = re.compile(r"(\.env\b|/\.env|wp-(login|admin|content|includes|config)|wordpress|xmlrpc\.php|phpmyadmin|/pma\b|/\.git(/|$)|/\.svn|/\.hg|\.php(\?|$)|cgi-bin|/\.aws|/\.ssh|/boaform|/HNAP1|/shell\b|\.asp(x)?(\?|$)|/vendor/phpunit|/actuator|/solr/|/console/|\.\./|/etc/passwd|/server-status|/\.DS_Store|/config\.json$|/sftp-config|/\.vscode|/owa/|/autodiscover|/remote/login|/geoserver|/manager/html|/jenkins|/druid|/nacos|/telescope|/debug/default|/_profiler|/cdn-cgi/trace)", re.I)
ADMIN_P = re.compile(_ADMIN, re.I)
REAL_BROWSER = re.compile(r"Mozilla/5\.0 \((Windows|Macintosh|iPhone|iPad|Linux; Android|X11)", re.I)

HOSTING_ORG = re.compile(r"amazon|aws|google( llc|cloud)|microsoft|azure|digitalocean|ovh|hetzner|linode|akamai|vultr|choopa|alibaba|aliyun|tencent|oracle|contabo|m247|leaseweb|scaleway|upcloud|hostinger|ionos|godaddy|cloudflare|fastly|datacamp|colocrossing|psychz|quadranet|servers ?com|hostwinds|kamatera|cdn77|g-core|gcore|zenlayer|huawei cloud|baidu|ucloud|kingsoft|bytedance|volcengine|censys|shodan|internet measurement|palo alto|stark industries|pfcloud|aeza|ponynet|frantech|buyvm|racknerd|dedipath|netcup|hivelocity|equinix|digital ocean|globalconnect|cogent|hurricane electric|data ?center|hosting|server|vps|cloud", re.I)
TW_ISP = [
    (re.compile(r"chunghwa|hinet|中華電信", re.I), "中華電信 HiNet"),
    (re.compile(r"taiwan mobile|台灣大哥大|twm|taiwanmobile|tbcnet|台灣寬頻", re.I), "台灣大哥大"),
    (re.compile(r"far ?eastone|fetnet|遠傳|seed net|seednet|new century", re.I), "遠傳／Seednet"),
    (re.compile(r"asia pacific telecom|aptg|亞太", re.I), "亞太電信"),
    (re.compile(r"so-?net", re.I), "So-net"),
    (re.compile(r"kbro|凱擘", re.I), "凱擘寬頻"),
    (re.compile(r"taiwan fixed network|tfn|台灣固網", re.I), "台灣固網"),
    (re.compile(r"chief telecom|是方", re.I), "是方電訊"),
    (re.compile(r"taiwan intelligent fiber|taifo|台灣智慧光網", re.I), "台灣智慧光網"),
    (re.compile(r"taiwan star|台灣之星", re.I), "台灣之星"),
    (re.compile(r"taiwan academic|tanet|教育部", re.I), "台灣學術網路 TANet"),
    (re.compile(r"giga ?media|cht|homeplus|大豐|tbc|北都|台固媒體|新永安|全球|群健|南天", re.I), "台灣有線寬頻"),
]
# 已知機構：(網段特徵, 身分, 標籤, 備註)。只在沒有攻擊行為時套用；有掃描路徑一律走惡意判定。
KNOWN_ORG = [
    (re.compile(r"palo alto networks|LOANED-SPACE-TO-PALO-ALTO", re.I), "hosting", "資安公司掃描器（Palo Alto Cortex Xpanse）",
     "資安公司對全網做資產盤點的例行掃描，不是針對你；目前沒打攻擊路徑，不封。"),
    (re.compile(r"censys|shodan|shadowserver|rapid7|onyphe|stretchoid|internet measurement|recyber|leakix|criminal ip|binaryedge", re.I), "hosting",
     "資安研究掃描器", "資安研究／搜尋引擎（Censys、Shodan 這類）在掃全網，不是針對你；出現攻擊路徑會自動封鎖。"),
    (re.compile(r"meta platforms|facebook", re.I), "platform", "Facebook／IG 連結安全檢查",
     "Meta 的伺服器用瀏覽器身分預先打開網址做安全檢查／預覽（有人在 FB、IG、Messenger 分享了連結），不是真人。"),
    (re.compile(r"microsoft|MSFT", re.I), "platform", "Microsoft 連結安全檢查（Outlook／Teams／Defender）",
     "微軟雲端用瀏覽器身分預先打開網址做安全掃描，常見於有人在 Outlook、Teams 傳了你的連結；不是真人。"),
    (re.compile(r"^.*\bGOGL\b|google llc", re.I), "hosting", "Google 雲端／Google 服務",
     "Google 的網段（Google Cloud 程式、Gmail／Chat 連結檢查或 Google 服務）；不是一般真人上網。"),
    (re.compile(r"amazon|aws", re.I), "hosting", "AWS 雲端主機", "Amazon AWS 機房的程式，不是真人上網；目前沒有攻擊行為，持續觀察。"),
    (re.compile(r"akamai|linode", re.I), "hosting", "Akamai／Linode 雲端主機", "Akamai／Linode 機房的程式，不是真人上網；目前沒有攻擊行為，持續觀察。"),
]
MOBILE_HINT = re.compile(r"mobile|wireless|lte|4g|5g|cellular|dynamic-ip-mobile|emome|行動", re.I)


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (now_s(), msg))
    except Exception:
        pass


def load_json(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(p, data):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def ts_of(t):
    m = re.match(r"(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)", t or "")
    if not m:
        return 0
    n = datetime.datetime.now()
    y = n.year - (1 if int(m.group(1)) > n.month else 0)
    try:
        return datetime.datetime(y, int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))).timestamp()
    except Exception:
        return 0


# ---------------- 1. 彙整行為 ----------------
_COMBINED = re.compile(r'^(\S+) \S+ \S+ \[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})[^\]]*\] "(?:\S+) (\S+)[^"]*" \d{3} \S+ "([^"]*)" "([^"]*)"')
_MON = {m: i + 1 for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_line(line):
    """JSON Lines（預設）或 nginx/Apache combined 格式 → {t, ip, cty, p, q, ref, ua, kind}"""
    if LOG_FORMAT == "combined":
        m = _COMBINED.match(line)
        if not m:
            return None
        ip, dd, mon, yy, hh, mi, ss, url, ref, ua = m.groups()
        p, _, q = url.partition("?")
        return {"t": "%02d-%s %s:%s:%s" % (_MON.get(mon, 1), dd, hh, mi, ss), "ip": ip, "cty": "", "p": p, "q": q,
                "ref": "" if ref == "-" else ref, "ua": "" if ua == "-" else ua}
    try:
        return json.loads(line)
    except Exception:
        return None


def aggregate():
    st = {}
    try:
        f = open(VISITLOG, encoding="utf-8", errors="replace")
    except Exception as e:
        log("讀不到 _visits.log: %s" % e)
        return st
    with f:
        for line in f:
            r = parse_line(line)
            if not r:
                continue
            ip = r.get("ip")
            if not ip:
                continue
            s = st.get(ip)
            if s is None:
                s = st[ip] = {"n": 0, "ua": collections.Counter(), "paths": collections.Counter(), "scan": collections.Counter(),
                              "mins": collections.Counter(), "first": r.get("t", ""), "last": "", "cty": "", "admin": 0, "self_ua": 0}
            s["n"] += 1
            ua = r.get("ua") or ""
            p = r.get("p") or ""
            full = p + ("?" + r["q"] if r.get("q") else "")
            s["ua"][ua] += 1
            s["paths"][p] += 1
            if SCAN_P.search(full):
                s["scan"][p] += 1
            if ADMIN_P.search(p):
                s["admin"] += 1
            if SELF_UA.search(ua) or r.get("kind") == "monitor":
                s["self_ua"] += 1
            s["mins"][int(ts_of(r.get("t")) // 60)] += 1
            s["last"] = r.get("t", "")
            if r.get("cty"):
                s["cty"] = r["cty"]
    return st


# ---------------- 2. 反查 ----------------
def ptr(ip):
    res = [None]

    def go():
        try:
            res[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            res[0] = ""
    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(4)
    return res[0] or ""


def _vcard_fn(ent):
    try:
        for it in ent.get("vcardArray", [None, []])[1]:
            if it[0] == "fn":
                return it[3]
    except Exception:
        pass
    return ""


def rdap(ip):
    url = "https://rdap.org/ip/" + ip
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read().decode("utf-8", "replace"))
    # 只取「組織」：跳過個人聯絡人（kind=individual，不收個資）與 IRT/abuse 群組
    orgs = []

    def take(e):
        roles = e.get("roles") or []
        kind = ""
        try:
            kind = next((it[3] for it in e.get("vcardArray", [None, []])[1] if it[0] == "kind"), "")
        except Exception:
            pass
        fn = _vcard_fn(e)
        if fn and "registrant" in roles and re.search(r"-(MAINT|MNT)$", fn, re.I):   # RIPE 維護者帳號＝組織
            orgs.append(re.sub(r"-(MAINT|MNT)$", "", fn, flags=re.I).title())
            return
        if not fn or kind == "individual" or "abuse" in roles or fn.startswith("IRT-"):
            return
        if kind == "org" or "registrant" in roles:
            orgs.append(fn)
    for e in d.get("entities", []) or []:
        take(e)
        for sub in e.get("entities", []) or []:
            take(sub)
    descs = []
    for x in (d.get("remarks") or []):
        dl = x.get("description") or []
        if dl and not re.match(r"(This information|Please|-{3}|Geofeed|Abuse)", dl[0], re.I):
            descs.append(dl[0].strip())
    if not orgs and descs:
        orgs.append(descs[0])
    if not orgs:   # 退而求其次：任何非個人、非 abuse 的實體名稱
        for e in (d.get("entities") or []):
            try:
                kind = next((it[3] for it in e.get("vcardArray", [None, []])[1] if it[0] == "kind"), "")
            except Exception:
                kind = ""
            fn = _vcard_fn(e)
            if fn and kind != "individual" and "abuse" not in (e.get("roles") or []) and not fn.startswith("IRT-"):
                orgs.append(fn)
                break
    if not orgs:   # 最後：abuse 群組名稱通常就是機構名（例：Microsoft Abuse Contact）
        for e in (d.get("entities") or []):
            fn = _vcard_fn(e)
            if fn and "abuse" in (e.get("roles") or []) and not fn.startswith("IRT-"):
                nm = re.sub(r"\s*(abuse.*|noc.*|network operations.*)$", "", fn, flags=re.I).strip()
                if len(nm) > 2:
                    orgs.append(nm)
                    break
    remarks = " ".join(descs)
    cidr = ""
    try:
        c = (d.get("cidr0_cidrs") or [])[0]
        cidr = "%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length"))
    except Exception:
        if d.get("startAddress") and d.get("endAddress"):
            try:
                nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(d["startAddress"]), ipaddress.ip_address(d["endAddress"])))
                cidr = str(nets[0]) if len(nets) == 1 else "%s - %s" % (d["startAddress"], d["endAddress"])
            except Exception:
                cidr = "%s - %s" % (d["startAddress"], d["endAddress"])
    # 去重、去掉註冊管理機構本身
    seen, clean = set(), []
    for o in orgs:
        if o and o not in seen and not re.search(r"Network Information Cent|APNIC|ARIN|RIPE|LACNIC|AFRINIC|IRT-|Asia Pacific Network", o, re.I):
            seen.add(o)
            clean.append(o)
    return {"net_name": d.get("name") or "", "net_handle": d.get("handle") or "", "country": d.get("country") or "",
            "org": "；".join(clean[:2]), "remarks": remarks[:200], "cidr": cidr,
            "start": d.get("startAddress") or "", "end": d.get("endAddress") or ""}


def in_range(ip, info):
    try:
        a = ipaddress.ip_address(ip)
        return ipaddress.ip_address(info["start"]) <= a <= ipaddress.ip_address(info["end"])
    except Exception:
        return False


# ---------------- 3. 判定 ----------------
def peak(s):
    return max(s["mins"].values()) if s["mins"] else 0


def top_ua(s):
    return s["ua"].most_common(1)[0][0] if s["ua"] else ""


def classify(ip, s, net, self_ips):
    ua = top_ua(s)
    uas = list(s["ua"].keys())
    org_text = " ".join([net.get("org", ""), net.get("net_name", ""), net.get("remarks", ""), net.get("ptr", "")])
    ev = []   # 證據
    if net.get("ptr"):
        ev.append("反查主機名：" + net["ptr"])
    if net.get("org") or net.get("net_name"):
        ev.append("網段擁有者：" + (net.get("org") or net.get("net_name")) + ((" ／ " + net["cidr"]) if net.get("cidr") else ""))
    ev.append("造訪 %d 次，每分鐘峰值 %d，頁面 %d 種，%s ～ %s" % (s["n"], peak(s), len(s["paths"]), s["first"], s["last"]))
    ev.append("主要 UA：" + (ua[:110] or "（無）"))
    scan_n = sum(s["scan"].values())
    if scan_n:
        ev.append("掃描／攻擊路徑：" + "、".join(list(s["scan"].keys())[:5]))

    def out(kind, label, conf, note, action=""):
        return {"kind": kind, "label": label, "confidence": conf, "note": note, "evidence": ev, "action": action}

    # 自家
    if s["self_ua"] or ip in self_ips:
        return out("self", "自家伺服器／健康檢查", "確定", "自家監控程式（config 的 self_ua_markers）的出口 IP，也就是你伺服器目前的對外 IP。")

    # 平台連結預覽
    for rx, name in PLATFORM_UA:
        if any(rx.search(u) for u in uas):
            line_net = bool(re.search(r"\bLINE\b|line-apps|LY Corp|NAVER", org_text, re.I))
            fb_net = bool(re.search(r"facebook|meta platforms|fbsv|tfbnw", org_text, re.I))
            verified = (name.startswith("LINE") and line_net) or (name.startswith("Facebook") and fb_net)
            return out("platform", name, "確定" if verified else "高",
                       "有人在%s分享了你的網址，平台伺服器來抓標題和縮圖；不是攻擊，也不是真人點開。%s" % (name.replace(" 連結預覽", ""), "（UA 與網段擁有者一致）" if verified else ""))

    # 搜尋引擎
    for rx, name in SEARCH_UA:
        if any(rx.search(u) for u in uas):
            real = True
            p = net.get("ptr", "")
            if name.startswith("Google"):
                real = bool(re.search(r"\.(googlebot|google)\.com$", p))
            elif name.startswith("Bing"):
                real = p.endswith(".search.msn.com")
            elif name.startswith("Apple"):
                real = p.endswith(".applebot.apple.com")
            if not real and name.split()[0] in ("Google", "Bing", "Apple"):
                if scan_n:
                    return out("malicious", "冒充%s的掃描器" % name, "高", "UA 自稱 %s，但反查主機名不是官方網域，且有打攻擊路徑。" % name, "block")
                return out("hosting", "自稱%s（未驗證）" % name, "中", "UA 自稱 %s，但反查主機名不是官方網域，可能是冒充的爬蟲。" % name)
            return out("searchbot", name, "確定" if real else "高", "搜尋引擎／AI 服務爬蟲在收錄你的網頁，正常現象。")

    is_hosting = bool(HOSTING_ORG.search(org_text))
    is_tool = any(TOOL_UA.search(u) for u in uas) or not ua
    is_scanner_ua = any(SCANNER_UA.search(u) for u in uas)

    # 站長裝置（推定）：真瀏覽器＋打過站長專屬路徑
    tw_isp = next((nm for rx, nm in TW_ISP if rx.search(org_text)), "")
    if s["admin"] >= 2 and REAL_BROWSER.search(ua) and (s["cty"] == COUNTRY_HOME or tw_isp):
        dev = "iPhone" if "iPhone" in ua else "iPad" if "iPad" in ua else "Android 手機" if "Android" in ua else "Mac" if "Macintosh" in ua else "Windows 電腦" if "Windows" in ua else "裝置"
        inapp = "（LINE 內建瀏覽器）" if re.search(r"\bLine/", ua) else ""
        return out("boss", "%s的%s%s（推定）" % (OWNER, dev, inapp), "中",
                   "用真瀏覽器%s打開過%s專屬頁 %d 次；陌生人進不去這些頁面，推定是%s自己。" % ("（" + tw_isp + "）" if tw_isp else "", OWNER, s["admin"], OWNER))

    # 惡意掃描
    if scan_n or is_scanner_ua:
        who = net.get("org") or net.get("net_name") or "未知網段"
        return out("malicious", "惡意掃描" + ("（雲端主機）" if is_hosting else ""), "確定" if scan_n >= 2 or is_scanner_ua else "高",
                   "在找漏洞（打 %s 這類不存在的管理/設定檔路徑），來源 %s。已自動封鎖。" % ("、".join(list(s["scan"].keys())[:2]) or "掃描器特徵", who), "block")

    # 已知機構（網段擁有者明確）→ 具體身分
    for rx, kind, label, note in KNOWN_ORG:
        if rx.search(org_text) and not scan_n:
            if kind == "platform" and not REAL_BROWSER.search(ua):
                continue
            return out(kind, label, "高", note)

    # Cloudflare 網路（自家門牌 Worker、WARP 使用者、或經 Cloudflare 代理的服務）
    if re.search(r"cloudflare", org_text, re.I) and not scan_n:
        return out("hosting", "Cloudflare 網路（Worker／WARP／代理）", "中",
                   "來自 Cloudflare 的網段：可能是我們自家門牌 Worker 轉發、Cloudflare WARP 使用者，或別的服務經 Cloudflare 代理；目前無攻擊行為。")

    # 雲端主機
    if is_hosting or (is_tool and not REAL_BROWSER.search(ua)):
        who = net.get("org") or net.get("net_name") or "雲端主機"
        tool = "程式工具（%s）" % ua.split("/")[0][:30] if is_tool and ua else "無 UA" if not ua else "瀏覽器 UA"
        return out("hosting", "雲端主機／自動程式", "高" if is_hosting else "中",
                   "來源是 %s 的機房，%s，不是真人上網；目前沒有攻擊行為，持續觀察（出現掃描路徑會自動封鎖）。" % (who, tool))

    # 一般訪客
    mobile = bool(MOBILE_HINT.search(org_text)) or bool(re.search(r"iPhone|Android|Mobile", ua))
    dev = "手機" if mobile else "電腦"
    inapp = "，從 LINE 內點開" if re.search(r"\bLine/", ua) else "，從 FB/IG 內點開" if re.search(r"FBAN|FBAV|Instagram", ua) else ""
    where = tw_isp or (net.get("org") or net.get("net_name") or "")
    hot = peak(s) >= 25
    return out("human", "一般訪客（%s%s）" % (s["cty"] or net.get("country") or "?", "・" + where if where else ""), "高" if REAL_BROWSER.search(ua) else "中",
               "真人用%s瀏覽%s，看了 %d 種頁面。%s" % (dev, inapp, len(s["paths"]), "每分鐘峰值偏高，留意是否在大量抓取。" if hot else ""))


# ---------------- 4. 主流程 ----------------
def run(dry=False, recheck=False, max_lookups=None):
    global MAX_LOOKUPS
    if max_lookups:
        MAX_LOOKUPS = max_lookups
    t0 = time.time()
    st = aggregate()
    notes = load_json(NOTES, {})
    meta = notes.get("_meta", {})
    nets = {} if recheck else notes.get("_nets", {})       # 網段快取：handle -> info（recheck 時清空重抓）
    ips = notes.get("ips", {})
    bl = load_json(BLOCKLIST, {})
    self_ips = {ip for ip, s in st.items() if s["self_ua"]}
    looked, added, blocked = 0, 0, []
    now = time.time()

    def cached_net(ip):
        for h, info in nets.items():
            if in_range(ip, info) and (info.get("org") or not RECHECK_EMPTY):
                return info
        return None

    order = sorted(st.keys(), key=lambda k: -st[k]["n"])
    for ip in order:
        s = st[ip]
        old = ips.get(ip) or {}
        age = now - old.get("_checked", 0)
        need_lookup = recheck or not old or age > RECHECK_DAYS * 86400 or (RECHECK_EMPTY and not (old.get("net") or {}).get("org"))
        net = dict(old.get("net") or {})
        if need_lookup and looked < MAX_LOOKUPS:
            info = cached_net(ip)
            if info is None:
                try:
                    info = rdap(ip)
                    if info.get("net_handle") or info.get("start"):
                        nets[info.get("net_handle") or info.get("start")] = info
                except Exception as e:
                    info = {"error": str(e)[:80]}
                    log("RDAP 失敗 %s: %s" % (ip, e))
                time.sleep(0.4)
            net = {k: info.get(k, "") for k in ("net_name", "org", "country", "cidr", "remarks")}
            net["ptr"] = ptr(ip)
            looked += 1
            old["_checked"] = now
        res = classify(ip, s, net, self_ips)
        if not old.get("label"):
            added += 1
        old.update(res)
        old["net"] = net
        old["stats"] = {"n": s["n"], "first": s["first"], "last": s["last"], "peak": peak(s), "pages": len(s["paths"]), "cty": s["cty"]}
        old["checked_at"] = datetime.datetime.fromtimestamp(old.get("_checked", now)).strftime("%Y-%m-%d %H:%M")
        if AUTO_BLOCK and res["action"] == "block" and ip not in bl and ip not in self_ips:
            blocked.append(ip)
            if not dry:
                bl[ip] = {"blocked_at": now_s(), "reason": "auto:intel", "note": res["label"] + "：" + res["note"][:120]}
        if ip in bl:
            old["blocked"] = True
        else:
            old.pop("blocked", None)
        ips[ip] = old

    counts = collections.Counter(v.get("kind") for v in ips.values())
    meta.update({"version": VERSION, "last_run": now_s(), "took_sec": round(time.time() - t0, 1), "lookups": looked,
                 "total": len(ips), "counts": dict(counts), "auto_blocked_last_run": blocked})
    out = {"_meta": meta, "_nets": nets, "ips": ips}
    if dry:
        for ip in order[:40]:
            v = ips[ip]
            print("%-40s %-10s %-28s %s" % (ip, v["kind"], v["label"][:28], v["note"][:60]))
        print(json.dumps(meta, ensure_ascii=False))
        return
    if blocked:
        with Lock("blocklist", timeout=10, stale=60):
            cur = load_json(BLOCKLIST, {})          # 重讀：期間可能有人從視窗／OSCLAW 封鎖或解封
            for ip in blocked:
                if ip not in cur:
                    cur[ip] = bl[ip]
            save_json(BLOCKLIST, cur)
    save_json(NOTES, out)
    log("run v%s：%d IP，反查 %d，新備註 %d，自動封鎖 %d %s，%.1fs" % (VERSION, len(ips), looked, added, len(blocked), blocked[:5], time.time() - t0))


def main():
    a = sys.argv[1:] or ["run"]
    mx = int(a[a.index("--max") + 1]) if "--max" in a else None
    if a[0] in ("block", "unblock") and len(a) > 1:
        (block_ip(a[1], "manual", " ".join(a[2:])) if a[0] == "block" else unblock_ip(a[1]))
        print("ok")
        return
    if a[0] == "show" and len(a) > 1:
        print(json.dumps(load_json(NOTES, {}).get("ips", {}).get(a[1]), ensure_ascii=False, indent=1))
        return
    if a[0] not in ("run", "recheck", "recheck-empty"):
        print(__doc__)
        return
    lk = Lock("ip_intel", timeout=0, stale=1800)
    if not lk.acquire():
        log("另一輪 IP 巡檢還在跑，這次略過")
        print("busy")
        return
    try:
        if a[0] == "run":
            run(dry="--dry" in a, max_lookups=mx)
        elif a[0] == "recheck":
            run(recheck=True, max_lookups=mx)
        else:
            global RECHECK_EMPTY
            RECHECK_EMPTY = True
            run(max_lookups=mx or 400)
    finally:
        lk.release()
    if "--dry" not in a:
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
