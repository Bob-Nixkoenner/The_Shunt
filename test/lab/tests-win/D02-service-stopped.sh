ID=D02
TITLE="Dienst gestoppt: Kill-Switch hält"
EXPECT_CANARY=none
CLIENT='
Stop-Service Shunt -WarningAction SilentlyContinue
Start-Sleep 3
& C:\lab\labtun.exe -s -m4 -o NUL http://1.1.1.1/; if ($LASTEXITCODE -eq 0) { "FAIL Tunnel-App kam ohne Dienst raus" }
& C:\lab\labfree.exe -s -m4 -o NUL http://1.1.1.1/; if ($LASTEXITCODE -eq 0) { "INFO App ohne Regel kam ohne Dienst raus" }
Resolve-DnsName $c -Server 10.77.0.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
Start-Service Shunt; Start-Sleep 8
'
