# OhmGateShield 🛡️ 門牌防護中心

**自架網站的看門人**：連進你網站的每個 IP 是誰，自動查清楚、寫備註，惡意掃描自動封鎖；
你實際在跑的軟體有沒有中已知漏洞，每天自動比對，安全範圍內自動修補。

**A gatekeeper for self-hosted sites.** Identify every IP that hits your server, write a plain-language note for each,
auto-block vulnerability scanners — and every day, check whether anything you actually run has a known
vulnerability, then patch it safely.

零依賴（只用 Python 標準函式庫）· Windows / Linux · MIT

---

## 為什麼做這個

一人公司把網站從自己電腦經 tunnel 開給外面看。某天台灣駭客年會發了 PHP2Shell（CVSS 9.2）重大漏洞警示，
真正的問題不是「我知不知道這個 CVE」，而是：

1. **我在跑的東西到底有沒有中？**（答案：PHP 根本沒裝——但要能「自動」知道）
2. **現在連進來的這幾百個 IP，誰是真人、誰是機器、誰在找漏洞？**

訪客紀錄裡 324 個 IP，人工看根本看不完。OhmGateShield 第一次跑完的結果長這樣：

| 身分 | 數量 | 例子 |
|---|---|---|
| 平台連結預覽 | 142 | Outlook／Teams 連結安全檢查、FB、LINE（有人分享了你的網址） |
| 一般訪客 | 80 | 中華電信、台灣大哥大、遠傳的手機與電腦 |
| 雲端主機 | 62 | 其中 31 個是資安公司（Palo Alto）的全網盤點掃描 |
| 自家 | 29 | 自己的健康檢查程式（浮動 IP） |
| 站長裝置（推定） | 8 | 自己的 iPhone——原本被誤判成「高風險」 |
| 搜尋引擎 | 3 | 驗證過官方網域的 Googlebot |

漏洞巡檢第一次盤點：20 個 Python／npm 環境、4,179 個套件，對外服務用到的套件有 212 筆已知漏洞；**安全自動修補 19 個套件後降到 112 筆**，0 個新依賴衝突，另外 6 個因會和其他套件衝突而自動退回、11 個跨大版本列為「需評估」。

## 兩個引擎＋一個儀表板

### `ip_intel.py` — IP 身分辨識＋自動封鎖（建議每小時）
- 反查 **PTR**（主機名）＋ **RDAP**（網段擁有者，同網段快取）＋ **行為**（掃描路徑、每分鐘峰值、UA、有沒有開站長專屬頁）
- 判定 7 種身分，每個 IP 都有「把握度＋一句話備註＋證據」
- Googlebot／Bingbot／Applebot **驗證官方網域**，冒充的抓出來
- 打 `.env`、`wp-login.php`、`phpmyadmin`、`.git`、路徑穿越……或用 zgrab／masscan／nuclei 的 → **自動寫進封鎖檔**
- 自家、站長、平台預覽、搜尋引擎**永不自動封**（封了 LINE／FB 預覽就失效）
- 不收個資：RDAP 裡的個人聯絡人一律略過，只記組織名

### `vuln_watch.py` — 漏洞情報＋安全自動修補（建議每天）
- 盤點：對外服務的 Python、其他直譯器與 `.venv`、`package-lock.json`、Node.js／cloudflared／Git／Chrome／作業系統版本，以及**不該存在的伺服器軟體**（PHP／Apache／Nginx／XAMPP）
- **OSV.dev** 批次比對（PyPI／npm／Go）→ 嚴重度、CVE、修補版本
- **CISA KEV**（已遭實際攻擊利用的漏洞）近 30 天新增、且是你有裝的產品
- `--patch`：只修對外服務那個 Python，而且：
  - 一次一個套件、`--no-deps`、只在**同一個大版本內**升級（0.x 套件看次版號）
  - 修前 `pip freeze` 備份；每個套件 import 測試＋ `pip check` 對照，有新衝突就**只退回那一個**
  - 最後安全網：本輪成功修補以外的任何版本變動，全部還原
  - 核心套件（torch、numpy、fastapi、pydantic…）與跨大版本的，只列「需評估」，絕不動
  > 為什麼這麼保守？開發時第一版用一般 `pip install`，結果連帶把 Pillow 9→13、starlette 0.37→1.0 升上去，fastapi 直接壞掉。我們用備份完整還原後，把流程改成上面這樣。

### `dashboard.html` — 單檔儀表板
網頁門牌（風險排行、即時訪客、封鎖清單、IP 詳情與證據）＋漏洞情報（盤點、漏洞表、自動修補結果、KEV）＋版本紀錄。白天／黑夜、手機可用。

## 快速開始

```bash
git clone https://github.com/junglin830/OhmGateShield
cd OhmGateShield
cp config.example.json config.json      # 改成你的路徑
python selftest.py                        # 17 個情境，不連網
python ip_intel.py run --dry              # 先看判定，不寫檔
python ip_intel.py run                    # 正式：寫 ip_notes.json、封鎖惡意
python vuln_watch.py run                  # 漏洞盤點
python vuln_watch.py patch --dry          # 看修補計畫
python vuln_watch.py run --patch          # 盤點＋安全修補＋重掃
```

把 `dashboard.html` 和輸出的 JSON 放在同一個網站目錄（**放在需要登入的管理區**，不要公開），開頁就看得到。

### 排程
- Linux：`0 * * * * python3 /path/ip_intel.py run`、`30 9 * * * python3 /path/vuln_watch.py run --patch`
- Windows：工作排程器每小時／每天，建議用 `pythonw.exe` 經 VBS 隱藏執行，不跳黑窗。

### 訪客紀錄格式
JSON Lines，一行一個請求：
```json
{"t": "10-22 10:02:00", "ip": "198.51.100.23", "cty": "TW", "p": "/shop", "q": "a=1", "ref": "https://www.google.com/", "ua": "Mozilla/5.0 ..."}
```
或直接用 nginx／Apache **combined** 格式（`"log_format": "combined"`）。`cty` 可用 Cloudflare 的 `CF-IPCountry` 標頭。

### 封鎖怎麼生效
引擎只負責寫 `blocked_ips.json`（`{ip: {blocked_at, reason, note}}`）。讓你的伺服器每次請求讀這份清單、命中就回 404／403，或用腳本同步到 nginx `deny`、防火牆規則。

## 設定 `config.json`
| 欄位 | 說明 |
|---|---|
| `visit_log` / `log_format` | 訪客紀錄路徑；`jsonl` 或 `combined` |
| `blocklist` / `ip_notes` | 封鎖檔、身分備註輸出 |
| `auto_block` | `false` ＝只判定不封鎖 |
| `self_ua_markers` | 你自己監控程式的 UA，IP 視為自家 |
| `owner_paths_regex` | 只有站長能開的路徑（用來認出你自己的手機） |
| `home_country` | 你所在國家碼，配合站長判定 |
| `exposed_python` | 跑對外服務的 Python（會被自動修補） |
| `other_pythons` / `scan_root` | 其他要盤點的直譯器、要掃 `.venv`／`package-lock.json` 的根目錄 |
| `notify_command` | 選填：有新的嚴重漏洞或 KEV 時執行，訊息附在最後一個參數 |

## 資料來源與隱私
- RDAP：[rdap.org](https://rdap.org) bootstrap → 各區域註冊機構；只存組織名，不存個人聯絡人
- 漏洞：[OSV.dev](https://osv.dev)、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- 所有結果都存在你自己的機器上，不上傳任何訪客資料

## English quick summary
- `ip_intel.py`: PTR + RDAP + behaviour → 7 identities (self / owner / platform preview / search bot / human / hosting / malicious) with evidence; auto-blocks scanners; verifies Google/Bing/Apple bots by PTR; never stores RDAP personal contacts.
- `vuln_watch.py`: inventories pip/npm/binaries, matches OSV.dev + CISA KEV, and auto-patches the exposed interpreter conservatively (one package at a time, `--no-deps`, same major, freeze backup, import test + `pip check` diff, per-package rollback, final safety net).
- `dashboard.html`: single-file dashboard for both.
- Standard library only. Windows & Linux. MIT.

## 版本紀錄
見 [CHANGELOG.md](CHANGELOG.md)。

## 授權
MIT — 個人、公司都可免費使用。覺得有用請按顆 ⭐。
