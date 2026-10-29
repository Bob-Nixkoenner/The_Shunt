ID=E06
TITLE="Captive Portal: alles hängt am Portal"
MODE=captive
EXPECT_CANARY=none
NOTE="Tunnel-Apps dürfen nichts im Klartext senden. Portal-Erkennung von Windows (NCSI) und Shunt erscheinen ohne Prozess-Zuordnung als Fund und sind einzeln zu bewerten."
CLIENT='
Start-Sleep 8
& C:\lab\labtun.exe -s -m5 -o NUL "http://$c/"; if ($LASTEXITCODE -eq 0) { "FAIL Tunnel-App kam trotz Portal raus" }
& C:\lab\labfree.exe -s -m5 -o NUL "http://f-$c/"
'
