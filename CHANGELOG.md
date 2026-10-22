# Changelog

All notable changes to OhmShield（前身 OhmGateShield）. 版本規則：MVP = 1.0.0；小修改升最後碼、局部功能升中間碼、大改版升第一碼。

## [OhmShield 1.0.0] — 2026-10-22 · 升級成完整資安中心

### Added
- **One score, three lines**: `core/shield_status.py` merges 網頁門牌 / 漏洞情報 / 電腦 (OhmSecGuard report, optional) into a total score, traffic light (green / yellow / red) and a prioritised to-do list → `shield_status.json`.
- **One API**: `core/shield_api.py` — the only implementation of `/api/shield/*` (ui, status, visits[?tail=N], notes, blocklist, vuln, secguard, jobs, block, unblock, scan, patch). Every entry point forwards to it, so behaviour and data are always identical.
- **One UI page**: `ui/shield.html` — adds the total-score banner, to-do list, scan / patch buttons with job polling, and the 電腦 tab; all data through the API (token header supported).
- **Desktop app** `app/ohmshield_app.py` → `OhmShield.exe`: pywebview window + tray shield coloured by status, token-protected 127.0.0.1 server with Origin check, single instance, close-to-tray, works without any web server. `app/build.ps1` builds it in an isolated venv.
- **File locks** (`core/shield_common.py`): engines, block / unblock and patch never run over each other, whichever entry point triggered them; stale locks auto-expire.
- `ip_intel.py` 1.1.0: `block` / `unblock` CLI, `owner_label`, blocklist merge-on-write under lock (manual blocks made during a run are kept).
- `vuln_watch.py` 1.3.0: run-level lock, `vuln_cache`, `vuln_backup_dir`, `scan_skip_regex`; status refresh after every run.

### Changed
- Repository renamed OhmGateShield → **OhmShield**（GitHub 會自動轉址）. Engines moved to `core/`; `dashboard.html` replaced by `ui/shield.html`.

## [OhmGateShield 1.0.0] — 2026-10-22 · 首次開源 First public release

### IP Intel `ip_intel.py` v1.0.3
- Added: identifies **every** visitor IP from PTR + RDAP + behaviour and writes a human-readable note with evidence (`ip_notes.json`).
  每個 IP 自動判定身分：自家 self／站長 owner（推定）／平台連結預覽 platform／搜尋引擎 searchbot／一般訪客 human／雲端主機 hosting／惡意 malicious。
- Added: **auto-block** vulnerability scanners (`.env`, `wp-login`, `phpmyadmin`, `.git`, `.php`, path traversal, zgrab/masscan/nuclei UA…) into `blocked_ips.json` (`reason=auto:intel`). Self / owner / platform / search bots are never auto-blocked.
- Added: Google / Bing / Apple crawler verification by official PTR domain — impostors are flagged (and blocked if they probe attack paths).
- Added: known-org labels — LINE / Facebook / Microsoft link-safety scanners, Palo Alto Cortex Xpanse / Censys / Shodan research scanners, AWS / Google Cloud / Akamai / Cloudflare.
- Added: Taiwan ISP recognition（中華電信、台灣大哥大、遠傳、亞太、凱擘、台灣固網、台灣智慧光網…）and LINE / FB in-app browser detection.
- Added: input as JSON Lines or nginx/Apache **combined** log; network cache per RDAP range; `recheck`, `recheck-empty`, `--max`, `--dry`.
- Fixed (pre-release): LINE in-app browser (`Line/` UA) was mistaken for a bot; `/admin` was mistaken for a scan path.
- Fixed (pre-release): RDAP person contacts are never stored (privacy) — RIPE `*-MAINT` maintainers and abuse-group names are used as the org name instead.

### Vuln Watch `vuln_watch.py` v1.2.1
- Added: inventory of pip packages (exposed interpreter + other interpreters + `.venv` under `scan_root`), npm `package-lock.json`, binaries (Node.js, cloudflared, Git, Python, Chrome, OS) and **server software that should not be there** (PHP / Apache / Nginx / XAMPP).
- Added: OSV.dev batch lookup (PyPI / npm / Go) with severity, CVE aliases and fixed versions; CISA KEV entries added in the last 30 days that match your products.
- Added: **safe auto-patch** of the exposed interpreter — one package at a time with `--no-deps`, same major version only (0.x: same minor), pip-freeze backup first, import test + `pip check` diff per package, per-package rollback, and a final safety net that restores anything else that changed. Core / cross-major packages are listed as "needs review".
- Fixed (pre-release): a plain `pip install` cascaded dependency upgrades (Pillow 9→13, starlette 0.37→1.0 broke fastapi). Rewritten to the `--no-deps` one-at-a-time flow above; the incident environment was restored exactly from the freeze backup.
- Added: optional `notify_command` hook — only for new CRITICAL findings in the exposed interpreter that auto-patch could **not** fix, or new KEV entries (with `--patch`, findings are compared against the pre-patch report).
- First real run: 4,179 packages / 20 environments; exposed-interpreter findings 212 → 112 after patching 19 packages, 0 new conflicts; 6 auto-rolled back (would break other packages), 11 cross-major listed for review.

### Dashboard `dashboard.html`
- Added: 網頁門牌 — KPIs, human-visit trend, risk ranking with identity notes, live feed split into human / bot / self / system, blocklist with manual block, IP detail drawer with evidence.
- Added: 漏洞情報 — inventory KPIs, findings table (exposed first), auto-patch results, KEV list.
- Added: version history tab; light / dark theme; responsive layout.

### Origin 起源
Built after a Taiwanese security advisory (HITCON, 2026-10-22) about PHP2Shell (CVE-2026-109618/109619, CVSS 9.2).
The real question for a one-person studio was not "do I know about this CVE" but "does anything I actually run have it — and who is knocking on my door right now?"
