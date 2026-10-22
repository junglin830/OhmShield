# OhmShield 桌面程式打包（Windows）。在專案根目錄執行：powershell -ExecutionPolicy Bypass -File app\build.ps1
# 用獨立 venv（app\.venv），不碰系統 Python 的套件（避免影響對外服務）。
$ErrorActionPreference = 'Continue'   # PyInstaller 把 INFO 寫到 stderr，不能用 Stop
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path 'app\.venv\Scripts\python.exe')) {
  if (Get-Command uv -ErrorAction SilentlyContinue) { uv venv app\.venv --python 3.12 } else { python -m venv app\.venv }
}
$py = 'app\.venv\Scripts\python.exe'
if (Get-Command uv -ErrorAction SilentlyContinue) { uv pip install --python $py -r app\requirements.txt } else { & $py -m pip install -r app\requirements.txt }
& $py -c "import sys;sys.path.insert(0,'core');sys.path.insert(0,'app');import ohmshield_app as a;im=a.make_icon('green');im.save('app/ohmshield.ico',sizes=[(16,16),(32,32),(48,48),(64,64)])"
& $py -m PyInstaller --noconfirm --clean --onefile --windowed --name OhmShield --icon "$root\app\ohmshield.ico" `
  --paths "$root\core" --hidden-import shield_api --hidden-import shield_status --hidden-import shield_common `
  --add-data "$root\core;core" --add-data "$root\ui;ui" --distpath "$root\app\dist" --workpath "$root\app\build" --specpath "$root\app\build" "$root\app\ohmshield_app.py"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path 'app\dist\OhmShield.exe')) { Write-Host "BUILD FAILED ($LASTEXITCODE)"; exit 1 }
Copy-Item app\dist\OhmShield.exe .\OhmShield.exe -Force
Write-Host "OK -> $root\OhmShield.exe"
