# OhmSecGuard - optional read-only SYSTEM helper (run once from an elevated PowerShell).
# Collects what a normal user cannot read: Defender exclusions, hidden scheduled tasks (Tarrask), WMI persistence, VSS shadow copies.
$script = Join-Path $PSScriptRoot 'admin_collect.ps1'
$tr = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`""
schtasks.exe /create /tn OhmSecGuard_Admin /sc MONTHLY /d 1 /st 10:30 /ru SYSTEM /rl HIGHEST /tr $tr /f | Out-Null
$t = Get-ScheduledTask -TaskName OhmSecGuard_Admin
$t.Settings.StartWhenAvailable = $true
$t.Settings.ExecutionTimeLimit = 'PT5M'
$t | Set-ScheduledTask | Out-Null
Start-ScheduledTask -TaskName OhmSecGuard_Admin
Write-Host 'OK: OhmSecGuard_Admin registered (monthly, SYSTEM, read-only).'
