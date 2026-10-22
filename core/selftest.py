# -*- coding: utf-8 -*-
"""OhmShield 自我測試：不連網、不寫檔，只驗判定邏輯。用法：python core/selftest.py"""
import importlib.util, collections, os, sys
spec = importlib.util.spec_from_file_location("m", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_intel.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def S(ua, paths, cty="US", admin=0, selfua=0):
    return {"n": len(paths), "ua": collections.Counter({ua: len(paths)}), "paths": collections.Counter(paths),
            "scan": collections.Counter([p for p in paths if m.SCAN_P.search(p)]), "mins": collections.Counter({1: len(paths)}),
            "first": "a", "last": "b", "cty": cty, "admin": admin, "self_ua": selfua}

MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
IPH = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 Line/14.1"
CASES = [
    ("自家健康檢查", S("Mozilla/5.0 ohm-health", ["/"], "TW", selfua=1), {"org": "Chunghwa Telecom"}, "self", ""),
    (".env 掃描（DO）", S(MAC, ["/.env", "/wp-login.php"]), {"org": "DigitalOcean, LLC"}, "malicious", "block"),
    ("zgrab 掃描器", S("Mozilla/5.0 zgrab/0.x", ["/"]), {"org": "Censys"}, "malicious", "block"),
    ("冒充 Googlebot", S("Mozilla/5.0 (compatible; Googlebot/2.1)", ["/"]), {"org": "OVH SAS", "ptr": "vps.ovh.net"}, "hosting", ""),
    ("真 Googlebot", S("Mozilla/5.0 (compatible; Googlebot/2.1)", ["/"]), {"org": "Google LLC", "ptr": "crawl-66-249-66-1.googlebot.com"}, "searchbot", ""),
    ("LINE 預覽", S("facebookexternalhit/1.1;line-poker/1.0", ["/racing/"], "JP"), {"org": "LINE", "ptr": "poker-108.line-apps.com"}, "platform", ""),
    ("站長 iPhone", S(IPH, ["/admin", "/00_公司管理/x", "/figure/"], "TW", admin=2), {"org": "Taiwan Mobile Co., Ltd."}, "boss", ""),
    ("台灣真人（LINE 內開）", S(IPH, ["/figure/", "/menu3d/"], "TW"), {"org": "Taiwan Mobile Co., Ltd."}, "human", ""),
    ("微軟連結檢查", S(MAC, ["/"]), {"org": "Microsoft"}, "platform", ""),
    ("Palo Alto 盤點", S("Mozilla/5.0 (Windows NT 10.0)", ["/"]), {"org": "Palo Alto Networks, Inc"}, "hosting", ""),
    ("Palo Alto 打攻擊路徑", S("x", ["/.env"]), {"org": "Palo Alto Networks, Inc"}, "malicious", "block"),
    ("curl on AWS", S("curl/8.4", ["/"]), {"org": "Amazon.com, Inc."}, "hosting", ""),
    ("/admin 不算掃描", S(MAC, ["/admin"], "US"), {"org": "Comcast"}, "human", ""),
]
fail = 0
for name, s, net, kind, act in CASES:
    r = m.classify("1.2.3.4", s, net, set())
    ok = r["kind"] == kind and r["action"] == act
    fail += not ok
    print(("PASS" if ok else "FAIL"), name, "->", r["kind"], r["label"], r["action"])
# vuln_watch：修補版本挑選
spec2 = importlib.util.spec_from_file_location("v", os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_watch.py"))
v = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(v)
VC = [("挑高於目前的最小修補版", v.pick_fixed("2.6.3", ["2.5.0", "2.7.0", "2.8.0"]), "2.7.0"),
      ("0.x 次版號算大版本", v._major("0.14.0") != v._major("0.16.0"), True),
      ("同大版本", v._major("6.14.2") == v._major("6.21.1"), True),
      ("跨大版本", v._major("9.5.0") == v._major("12.3.0"), False)]
for name, got, want in VC:
    ok = got == want
    fail += not ok
    print(("PASS" if ok else "FAIL"), name, "->", got)
total = len(CASES) + len(VC)
print("%d/%d 通過" % (total - fail, total))
sys.exit(1 if fail else 0)
