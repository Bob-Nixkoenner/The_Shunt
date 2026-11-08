ID=X01
TITLE="NCSI-Probe (NlaSvc) mit gestopptem Dienst: kommt sie am Kill-Switch vorbei? (Eingrenzung WD05-2)"
EXPECT_CANARY=any
SETTLE=2
NOTE="Dienst gestoppt (Kill-Switch bleibt), dann NlaSvc neu starten (löst die NCSI-Probe aus), DNS über Dnscache, PowerShell-HTTP. Danach Dienst wieder an."
CLIENT='
Stop-Service Shunt -WarningAction SilentlyContinue; Start-Sleep 3
"svc: " + (Get-Service Shunt).Status
Resolve-DnsName "x01dns-$c" -DnsOnly -ErrorAction SilentlyContinue | Out-Null
try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 http://www.msftconnecttest.com/connecttest.txt).StatusCode } catch { "iwr ERR " + $_.Exception.Message }
Restart-Service NlaSvc -Force -WarningAction SilentlyContinue
Start-Sleep 25
(Get-NetConnectionProfile | % { $_.InterfaceAlias + " " + $_.IPv4Connectivity }) -join "; "
Start-Service Shunt -WarningAction SilentlyContinue; Start-Sleep 8
"svc: " + (Get-Service Shunt).Status
'
