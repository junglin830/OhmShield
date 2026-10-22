# OhmSecGuard admin helper (runs as SYSTEM via task OhmSecGuard_Admin). READ-ONLY.
# Writes Defender exclusions to secguard_data\admin_facts.json for the user-level scanner.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PSScriptRoot 'secguard_data\admin_facts.json'
$p = Get-MpPreference
$o = [ordered]@{
  ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  excl_path = @($p.ExclusionPath | Where-Object { $_ })
  excl_process = @($p.ExclusionProcess | Where-Object { $_ })
  excl_ext = @($p.ExclusionExtension | Where-Object { $_ })
  excl_ip = @($p.ExclusionIpAddress | Where-Object { $_ })
}
# v1.2.0: hidden scheduled tasks (Tarrask: SD removed/empty), WMI event-subscription persistence, recent VSS shadow copies
$hidden = @()
$tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
Get-ChildItem $tree -Recurse | ForEach-Object {
  $hasId = $null -ne (Get-ItemProperty $_.PSPath -Name Id -ErrorAction SilentlyContinue)
  if ($hasId) {
    $sd = (Get-ItemProperty $_.PSPath -Name SD -ErrorAction SilentlyContinue).SD
    if (-not $sd -or $sd.Length -eq 0) { $hidden += ($_.Name -replace '^.*\\Tree', '') }
  }
}
$o.hidden_tasks = @($hidden)
$wmi = @()
foreach ($cls in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
  Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue | ForEach-Object {
    $wmi += ($cls + '|' + $_.Name + '|' + [string]$_.CommandLineTemplate + [string]$_.ScriptFileName)
  }
}
$o.wmi_persist = @($wmi)
$since = (Get-Date).AddDays(-35)
$o.shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.InstallDate -gt $since } | ForEach-Object { $_.InstallDate.ToString('yyyy-MM-dd HH:mm') })
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$json = $o | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($out + '.tmp', $json, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -Force ($out + '.tmp') $out
