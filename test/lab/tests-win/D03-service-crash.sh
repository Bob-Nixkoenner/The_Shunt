ID=D03
TITLE="Dienst stürzt ab (taskkill /f): Kill-Switch hält bis zum Neustart"
EXPECT_CANARY=any
CLIENT='
taskkill /f /im shuntd-win.exe | Out-Null
1..5 | ForEach-Object { & C:\lab\labtun.exe -s -m2 -o NUL http://1.1.1.1/; & C:\lab\labfree.exe -s -m2 -o NUL "http://$_-$c/"; Start-Sleep 1 }
Start-Sleep 10; "Dienst: " + (Get-Service Shunt).Status
'
