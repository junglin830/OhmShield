# OhmSecGuard collector (user context, READ-ONLY). Outputs one JSON object to stdout.
# Never changes any setting. Called by _ohm_secguard.py with CREATE_NO_WINDOW.
param([string]$Out = '', [switch]$Quick)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# NOTE: do NOT set [Console]::OutputEncoding here - it hangs forever when started hidden from a scheduled task.
$o = [ordered]@{ ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); errors = @(); timing = [ordered]@{} }

function Try-Run([string]$name, [scriptblock]$sb) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try { & $sb } catch { $script:o.errors += ($name + ': ' + $_.Exception.Message) ; $null }
  $script:o.timing[$name] = [int]$sw.ElapsedMilliseconds
  # progress marker so a hung section can be identified from outside
  try { [IO.File]::WriteAllText("$PSScriptRoot\secguard_data\collect_progress.txt", ($name + ' done ' + (Get-Date).ToString('HH:mm:ss'))) } catch {}
}

# ---- Proxy (WinINet per-user) ----
$o.proxy = Try-Run 'proxy' {
  $k = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  [ordered]@{ ProxyEnable = [int]($k.ProxyEnable); ProxyServer = [string]$k.ProxyServer; ProxyOverride = [string]$k.ProxyOverride;
              AutoConfigURL = [string]$k.AutoConfigURL; AutoDetect = [string]$k.AutoDetect }
}
$o.proxy_policy = Try-Run 'proxy_policy' {
  $p = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
  if ($p) { [ordered]@{ ProxySettingsPerUser = [string]$p.ProxySettingsPerUser } } else { $null }
}
# WinHTTP: read the registry blob instead of netsh (netsh text is localized and gets garbled when run hidden)
$o.winhttp = Try-Run 'winhttp' {
  $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name WinHttpSettings -ErrorAction SilentlyContinue).WinHttpSettings
  if (-not $v -or $v.Length -lt 16) { 'direct' } else {
    $flags = [BitConverter]::ToInt32($v, 8); $len = [BitConverter]::ToInt32($v, 12)
    if (($flags -band 2) -eq 0 -or $len -le 0) { 'direct' } else {
      $srv = [Text.Encoding]::ASCII.GetString($v, 16, $len)
      $off = 16 + $len; $bl = ''
      if ($v.Length -ge $off + 4) { $bll = [BitConverter]::ToInt32($v, $off); if ($bll -gt 0) { $bl = [Text.Encoding]::ASCII.GetString($v, $off + 4, $bll) } }
      'proxy=' + $srv + $(if ($bl) { ' bypass=' + $bl } else { '' })
    }
  }
}
$o.env_proxy = Try-Run 'env' {
  $r = [ordered]@{}
  foreach ($scope in 'User','Machine') { foreach ($n in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy') {
    $v = [Environment]::GetEnvironmentVariable($n, $scope); if ($v) { $r["$scope`:$n"] = $v } } }
  $r
}
$o.tool_proxy = Try-Run 'tool_proxy' {
  $r = [ordered]@{}
  $gc = Join-Path $env:USERPROFILE '.gitconfig'
  if (Test-Path $gc) { $t = Get-Content $gc -Raw; foreach ($m in [regex]::Matches($t, '(?im)^\s*(https?proxy|proxy)\s*=\s*(.+)$')) { $r['git:' + $m.Groups[1].Value] = $m.Groups[2].Value.Trim() } }
  $npmrc = Join-Path $env:USERPROFILE '.npmrc'
  if (Test-Path $npmrc) { foreach ($line in Get-Content $npmrc) { if ($line -match '^\s*(https-proxy|proxy)\s*=\s*(.+)$') { $r['npm:' + $matches[1]] = $matches[2].Trim() } } }
  foreach ($pip in (Join-Path $env:APPDATA 'pip\pip.ini'), (Join-Path $env:USERPROFILE 'pip\pip.ini')) {
    if (Test-Path $pip) { foreach ($line in Get-Content $pip) { if ($line -match '^\s*proxy\s*=\s*(.+)$') { $r['pip:proxy'] = $matches[1].Trim() } } } }
  $r
}

# ---- Listening ports (to validate proxy target) + connection counts per process ----
# only needed when a proxy is switched on (to see whether its local port is alive) - skipping saves ~8s
$o.listen = @()
if ($o.proxy -and $o.proxy.ProxyEnable -eq 1) {
  $o.listen = Try-Run 'listen' { @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique) }
}
if (-not $Quick) {
$o.conn_top = Try-Run 'conn' {
  $g = Get-NetTCPConnection | Where-Object { $_.State -ne 'Listen' } | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 8
  @($g | ForEach-Object {
    $p = Get-Process -Id ([int]$_.Name)
    [ordered]@{ pid = [int]$_.Name; count = $_.Count; name = [string]$p.ProcessName; path = [string]$p.Path }
  })
}

}
# ---- hosts / DNS / dynamic ports ----
$o.hosts = Try-Run 'hosts' {
  $f = "$env:SystemRoot\System32\drivers\etc\hosts"
  $lines = @(Get-Content $f | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
  [ordered]@{ sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($f))) -replace '-',''); lines = $lines; mtime = (Get-Item $f).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
}

# ---- v1.2.0: ClickFix (Win+R history), browser policy proxy/forced extensions, root certificates, Defender config events ----
$o.runmru = Try-Run 'runmru' {
  $r = @()
  foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU','HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths') {
    $p = Get-ItemProperty $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'MRUList' } | ForEach-Object { $r += ((Split-Path $k -Leaf) + '|' + [string]$_.Value) } }
  }
  $r
}
$o.browser_policy = Try-Run 'browser' {
  $r = [ordered]@{}
  foreach ($hive in 'HKCU','HKLM') { foreach ($b in 'Google\Chrome','Microsoft\Edge','BraveSoftware\Brave') {
    $k = "$($hive):\Software\Policies\$b"
    $p = Get-ItemProperty $k
    if ($p) { foreach ($n in 'ProxyMode','ProxyServer','ProxyPacUrl','ProxySettings','ProxyBypassList') { if ($p.$n) { $r["$hive\$b\$n"] = [string]$p.$n } } }
    $f = Get-ItemProperty "$k\ExtensionInstallForcelist"
    if ($f) { $f.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $r["$hive\$b\ForceExt\$($_.Name)"] = [string]$_.Value } }
  } }
  $r
}
$o.rootcerts = Try-Run 'rootcerts' {
  $r = @()
  foreach ($st in 'CurrentUser','LocalMachine') { Get-ChildItem "Cert:\$st\Root" | ForEach-Object { $r += ($st + '|' + $_.Thumbprint + '|' + $_.Subject) } }
  $r
}
$o.def_policy = Try-Run 'defpolicy' {
  $r = [ordered]@{}
  Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $kp = [string]$_.Name
    $p = Get-ItemProperty $_.PSPath
    $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $r[(($kp -replace '^.*Windows Defender', '') + '\' + $_.Name)] = [string]$_.Value }
  }
  $p0 = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
  if ($p0) { $p0.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $r['\' + $_.Name] = [string]$_.Value } }
  $r
}
$o.def_events = Try-Run 'defevents' {
  $since = (Get-Date).AddDays(-35)
  @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001,5007,5010,5012,1116,1117; StartTime = $since } -MaxEvents 300 |
    ForEach-Object {
      $m = [string]$_.Message
      if ($_.Id -eq 5007 -and $m -notmatch '(?i)Exclusions|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableAntiSpyware|TamperProtection|DisableIOAV') { return }
      [ordered]@{ id = $_.Id; rec = [int64]$_.RecordId; time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); msg = ($m -replace '\s+', ' ').Substring(0, [Math]::Min(420, ($m -replace '\s+', ' ').Length)) }
    })
}

if (-not $Quick) {
$o.dns = Try-Run 'dns' {
  $up = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty ifIndex)
  @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $up -contains $_.InterfaceIndex -and $_.ServerAddresses } |
    ForEach-Object { [ordered]@{ ifname = $_.InterfaceAlias; servers = @($_.ServerAddresses) } })
}
$o.dynport = Try-Run 'dynport' {
  $t = Get-NetTCPSetting | Where-Object { $_.DynamicPortRangeStartPort } | Select-Object -First 1
  [ordered]@{ start = [int]$t.DynamicPortRangeStartPort; num = [int]$t.DynamicPortRangeNumberOfPorts }
}

# ---- Defender / Firewall / UAC / RDP ----
$o.defender = Try-Run 'defender' {
  $s = Get-MpComputerStatus
  [ordered]@{ rtp = [bool]$s.RealTimeProtectionEnabled; av = [bool]$s.AntivirusEnabled; tamper = [bool]$s.IsTamperProtected;
              sig_age = [int]$s.AntivirusSignatureAge; quick_age = [int]$s.QuickScanAge; full_age = [int]$s.FullScanAge }
}
$o.threats = Try-Run 'threats' {
  $since = (Get-Date).AddDays(-7)
  @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $since } | Select-Object -First 20 | ForEach-Object {
    [ordered]@{ time = $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm'); id = [string]$_.ThreatID; res = [string]($_.Resources -join ' | '); action = [int]$_.ThreatStatusID } })
}
$o.firewall = Try-Run 'firewall' { $r = [ordered]@{}; Get-NetFirewallProfile | ForEach-Object { $r[$_.Name] = [bool]($_.Enabled -eq 1 -or $_.Enabled -eq $true) }; $r }
$o.uac = Try-Run 'uac' { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
$o.rdp_deny = Try-Run 'rdp' { [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }

# ---- Scheduled tasks (what the user context can see) ----
$o.tasks = Try-Run 'tasks' {
  @(Get-ScheduledTask | ForEach-Object {
    $acts = @($_.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() }) -join ' && '
    [ordered]@{ key = ($_.TaskPath + $_.TaskName); state = [string]$_.State; author = [string]$_.Author; date = [string]$_.Date; act = $acts }
  })
}

# ---- Autostart ----
$o.autostart = Try-Run 'autostart' {
  $r = @()
  foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    $p = Get-ItemProperty $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $r += [ordered]@{ key = ($k + '\' + $_.Name); cmd = [string]$_.Value } } }
  }
  foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
    Get-ChildItem $d -File | ForEach-Object { $r += [ordered]@{ key = ('Startup\' + $_.Name); cmd = $_.FullName } }
  }
  $r
}

# ---- Known IOC from 2026-10-08 incident ----
$o.ioc = Try-Run 'ioc' {
  @(Get-ChildItem "$env:SystemRoot\System32" -Directory -Filter '*VersionAgent*' | Select-Object -ExpandProperty FullName)
}

}
$o.quick = [bool]$Quick
$json = $o | ConvertTo-Json -Depth 6 -Compress
if ($Out) { [IO.File]::WriteAllText($Out + '.tmp', $json, (New-Object System.Text.UTF8Encoding($false))); Move-Item -Force ($Out + '.tmp') $Out } else { $json }
