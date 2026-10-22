# OhmShield 🛡️ 歐姆資安中心

**一個分數、三條線、兩個入口。** 給自架網站和一人公司用的資安中心：

- 🌐 **網頁門牌**：連進你網站的每個 IP 是誰，自動查清楚並寫備註；惡意掃描自動封鎖。
- 🧬 **漏洞情報**：你實際在跑的軟體有沒有中已知漏洞，每天自動比對，安全範圍內自動修補。
- 💻 **電腦**：讀 [OhmSecGuard](https://github.com/junglin830/OhmSecGuard) 的 Windows 巡檢報告，合進總分（選填）。

三條線合成**總分＋紅黃綠燈＋待處理清單**。入口有兩個，用的是同一套引擎、同一份資料、同一個介面頁：

| 入口 | 適合 |
|---|---|
| **桌面視窗程式** `OhmShield.exe` | 右下角盾牌常駐顯示紅黃綠燈；不依賴網站伺服器，離線也能用 |
| **網頁／你的後台**（例如 Flask） | 手機遠端看；也可以接到聊天機器人查狀態 |

引擎零依賴（只用 Python 標準函式庫）· Windows／Linux · MIT

> 前身是 OhmGateShield 1.0.0（網頁門牌＋漏洞情報）。這一版把它升級成完整的資安中心。

---

## 為什麼做這個

一人公司把網站從自己電腦經 tunnel 開給外面看。某天台灣駭客年會發了 PHP2Shell（CVSS 9.2）重大漏洞警示，真正想知道的是：

1. **我在跑的東西到底有沒有中？**（PHP 根本沒裝，但要能「自動」知道）
2. **現在連進來的這幾百個 IP，誰是真人、誰是機器、誰在找漏洞？**
3. **電腦本身有沒有被動過？** 而且這三件事不要各看各的，要一眼看懂。

實際第一次跑的結果：
- **IP 身分**：324 個 IP 全部辨識完。平台連結預覽 142、一般訪客 80、雲端主機 62（其中 31 個是資安公司的全網盤點）、自家 29、站長自己的手機 8、搜尋引擎 3。
- **漏洞**：盤點 20 個 Python／npm 環境、4,179 個套件。對外服務用到的套件原本有 212 筆已知漏洞，**安全自動修補 19 個套件後剩 112 筆**，新增依賴衝突 0。

## 架構：同一套核心、兩個入口

```
OhmShield/
├─ core/            唯一的引擎與 API（標準函式庫）
│  ├─ ip_intel.py       IP 身分辨識＋自動封鎖（建議每小時）
│  ├─ vuln_watch.py     漏洞情報＋安全自動修補（建議每天）
│  ├─ shield_status.py  三條線合成總分／燈號／待處理
│  ├─ shield_api.py     /api/shield/* 唯一實作（兩個入口都呼叫它）
│  ├─ shield_common.py  設定、檔案鎖、封鎖清單
│  └─ selftest.py       17 個情境，不連網
├─ ui/shield.html   唯一的介面頁
├─ app/             桌面視窗程式外殼（pywebview＋常駐圖示，打包成 exe）
└─ config.json      你的路徑與規則（從 config.example.json 複製）
```

- **只有引擎會寫資料**：巡檢、封鎖／解封、修補都經過 `shield_common.Lock` 檔案鎖。視窗程式和網頁同時按，也不會互相蓋掉。
- **兩個入口互不依賴**：視窗程式直接讀本機檔案；網頁那邊掛了，視窗照樣能用，反過來也一樣。
- **權限交給外殼**：視窗程式每次啟動產生隨機 token，只有帶 token 的請求能讀寫資料，也會檢查 Origin。網頁入口請接你自己的登入驗證。

## 引擎重點

### IP 情報 `core/ip_intel.py`
- 反查 **PTR**＋**RDAP**（網段擁有者，同網段快取），再看**行為**（掃描路徑、每分鐘峰值、UA、有沒有開站長專屬頁）。
- 判定 7 種身分：自家、站長（推定）、平台連結預覽、搜尋引擎、一般訪客、雲端主機、惡意。每個 IP 附把握度、一句話備註和證據。
- Googlebot／Bingbot／Applebot 會**驗證官方網域**，冒充的會被抓出來。
- 打 `.env`、`wp-login.php`、`phpmyadmin`、`.git`、路徑穿越，或用 zgrab／masscan／nuclei 的 → **自動封鎖**。自家、站長、平台預覽、搜尋引擎**永不自動封**。
- RDAP 裡的個人聯絡人一律不存，只記組織名。
- 指令：`run`、`run --dry`、`recheck [--max N]`、`recheck-empty`、`show <ip>`、`block <ip> [備註]`、`unblock <ip>`。

### 漏洞情報 `core/vuln_watch.py`
- **盤點**：對外服務用的 Python、其他直譯器與 `.venv`、`package-lock.json`，以及 Node.js／cloudflared／Git／Chrome／作業系統的版本。也會抓**不該存在的伺服器軟體**（PHP／Apache／Nginx／XAMPP）。
- **比對**：OSV.dev（PyPI／npm／Go），以及 CISA KEV（已遭實際攻擊利用的漏洞）近 30 天新增、且是你有裝的產品。
- **`--patch` 安全修補**：
  - 一次一個套件、`--no-deps`、只在同一個大版本內升級。
  - 修前先做 freeze 備份。每個套件做 import 測試，再跟修補前的 `pip check` 對照；有新衝突就只退回那一個。
  - 最後一道安全網：本輪修好的以外，任何版本變動都還原。
  - 核心套件和需要跨大版本的，只列「需評估」，絕不動。
  > 為什麼這麼保守？第一版用一般的 `pip install`，結果連帶把 Pillow 9→13、starlette 0.37→1.0 都升上去，fastapi 直接壞掉。後來用備份完整還原，才改成現在的流程。

## 快速開始

```bash
git clone https://github.com/junglin830/OhmShield
cd OhmShield
cp config.example.json config.json         # 改成你的路徑
python core/selftest.py                      # 17/17
python core/ip_intel.py run                  # 寫 ip_notes.json、封鎖惡意
python core/vuln_watch.py run --patch        # 漏洞盤點＋安全修補
python core/shield_status.py                 # 印出總分與待處理
```

### 桌面視窗程式（Windows）
```powershell
powershell -ExecutionPolicy Bypass -File app\build.ps1    # 建獨立 venv、打包成 OhmShield.exe（放在專案根目錄）
.\OhmShield.exe            # 開視窗；加 --hidden 只常駐右下角
```
- 打包用獨立 venv（`app\.venv`），**不碰你系統 Python 的套件**。
- exe 會讀專案裡的 `core/`、`ui/`、`config.json`，所以更新引擎或介面都不用重新打包。
- 開機自動常駐：在工作排程器建一個「登入時」的工作，執行 `OhmShield.exe --hidden`。

### 接到你自己的網站／後台
把 `/api/shield/<路徑>` 轉給 `core/shield_api.handle(method, path, query, body)`，它會回傳 `(狀態碼, content-type, bytes)`，再套上你的登入驗證就好。Flask 範例：
```python
@app.route("/api/shield/<path:sub>", methods=["GET", "POST"])
def shield(sub):
    code, ctype, data = shield_api.handle(request.method, sub, request.args.to_dict(), request.get_json(silent=True) or {})
    return Response(data, status=code, content_type=ctype)
```
介面頁在 `/api/shield/ui`。

### 排程
- Linux：`0 * * * * python3 core/ip_intel.py run`、`30 9 * * * python3 core/vuln_watch.py run --patch`
- Windows：工作排程器每小時／每天執行，建議用 `pythonw.exe` 經 VBS 隱藏執行，不會跳黑窗。

### 訪客紀錄格式
JSON Lines，一行一個請求：
```json
{"t": "10-22 10:02:00", "ip": "198.51.100.23", "cty": "TW", "p": "/shop", "q": "a=1", "ref": "https://www.google.com/", "ua": "Mozilla/5.0 ..."}
```
也可以直接用 nginx／Apache **combined** 格式（設定 `"log_format": "combined"`）。封鎖結果寫在 `blocked_ips.json`，讓你的伺服器每次請求讀它、命中就回 404／403。

## 設定 `config.json`（重點欄位）
| 欄位 | 說明 |
|---|---|
| `visit_log` / `blocklist` / `ip_notes` | 訪客紀錄、封鎖清單、身分備註 |
| `auto_block` | `false` ＝只判定、不封鎖 |
| `self_ua_markers` | 你自己監控程式的 UA，這些 IP 視為自家 |
| `owner_paths_regex` / `owner_label` | 只有站長能開的路徑，用來認出你自己的裝置；顯示用的稱呼 |
| `exposed_python` / `engine_python` | 跑對外服務的 Python（會被自動修補）；背景執行引擎用的直譯器 |
| `scan_root` / `scan_skip_regex` | 要掃 `.venv`、`package-lock.json` 的根目錄；要略過的大資料夾 |
| `notify_command` | 有修不掉的新嚴重漏洞或新的 KEV 時執行（訊息附在最後一個參數） |
| `secguard_report` | OhmSecGuard 的 `report.json`，讓「電腦」這條線算進總分 |
| `status_file` / `lock_dir` | 總狀態檔、鎖檔資料夾 |

## 資料來源與隱私
- RDAP：[rdap.org](https://rdap.org)；只存組織名，不存個人聯絡人。
- 漏洞：[OSV.dev](https://osv.dev)、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)。
- 所有結果都存在你自己的機器上，不上傳任何訪客資料。

## English summary
OhmShield is a one-person security center for self-hosted sites: **IP intel** (PTR + RDAP + behaviour → 7 identities with evidence, auto-blocks scanners, verifies search-bot PTRs), **vuln watch** (pip/npm/binary inventory vs OSV.dev + CISA KEV, conservative auto-patching with per-package rollback) and an optional **PC line** from OhmSecGuard, merged into one score with a traffic light and a to-do list. One core, one data set, one UI page — two entry points: a Windows tray app (pywebview, token-protected local API, works offline) and any web backend that forwards `/api/shield/*` to `core/shield_api.handle()`. Engine: standard library only. MIT.

## 版本紀錄
見 [CHANGELOG.md](CHANGELOG.md)。

## 授權
MIT。個人、公司都可以免費使用。覺得有用請按顆 ⭐。
