# OhmSecGuard - register the two user-level scheduled tasks (no admin needed). Read-only scans.
#   OhmSecGuard        : full scan on day 1 of every month 10:37 (runs at next boot if missed)
#   OhmSecGuard_Quick  : event-triggered quick check - network connected (NetworkProfile 10000)
#                        or Defender config changed / threat found (5001,5007,5010,5012,1116,1117). No polling.
$here = $PSScriptRoot
$pyw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pyw) { Write-Error 'pythonw.exe not found in PATH'; exit 1 }
$user = "$env:USERDOMAIN\$env:USERNAME"
function Act($verb) { "<Exec><Command>wscript.exe</Command><Arguments>`"$here\run_hidden.vbs`" `"$pyw`" `"$here\secguard.py`" $verb</Arguments><WorkingDirectory>$here</WorkingDirectory></Exec>" }
function TaskXml($desc, $trig, $act) {
  "<?xml version=`"1.0`" encoding=`"UTF-16`"?><Task version=`"1.4`" xmlns=`"http://schemas.microsoft.com/windows/2004/02/mit/task`"><RegistrationInfo><Description>$desc</Description></RegistrationInfo><Triggers>$trig</Triggers><Principals><Principal id=`"Author`"><UserId>$user</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT10M</ExecutionTimeLimit><Priority>6</Priority></Settings><Actions Context=`"Author`">$act</Actions></Task>"
}
$start = (Get-Date -Day 1).AddMonths(1).ToString('yyyy-MM-01T10:37:00')
$monthly = "<CalendarTrigger><StartBoundary>$start</StartBoundary><Enabled>true</Enabled><ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/></Months></ScheduleByMonth></CalendarTrigger>"
$q1 = '&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;'
$q2 = '&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational"&gt;&lt;Select Path="Microsoft-Windows-Windows Defender/Operational"&gt;*[System[(EventID=5007 or EventID=5001 or EventID=5010 or EventID=5012 or EventID=1116 or EventID=1117)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;'
$events = "<EventTrigger><Enabled>true</Enabled><Delay>PT45S</Delay><Subscription>$q1</Subscription></EventTrigger><EventTrigger><Enabled>true</Enabled><Delay>PT20S</Delay><Subscription>$q2</Subscription></EventTrigger>"
Register-ScheduledTask -TaskName OhmSecGuard -Xml (TaskXml 'OhmSecGuard monthly read-only scan' $monthly (Act 'scan')) -Force | Out-Null
Register-ScheduledTask -TaskName OhmSecGuard_Quick -Xml (TaskXml 'OhmSecGuard event-triggered quick check' $events (Act 'quick')) -Force | Out-Null
Write-Host 'OK: OhmSecGuard (monthly) + OhmSecGuard_Quick (event-triggered) registered.'
