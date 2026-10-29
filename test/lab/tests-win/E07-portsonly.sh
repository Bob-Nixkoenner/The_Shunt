ID=E07
TITLE="Gäste-WLAN lässt nur 80/443 durch (Tunnel-UDP gesperrt)"
MODE=portsonly
EXPECT_CANARY=none
CLIENT='
Start-Sleep 5
& C:\lab\labtun.exe -s -m5 -o NUL "http://$c/"; if ($LASTEXITCODE -eq 0) { "FAIL Tunnel-App kam raus, obwohl der Tunnel gesperrt ist" }
& C:\lab\labfree.exe -s -m5 -o NUL https://example.com/; if ($LASTEXITCODE -eq 0) { "FAIL App ohne Regel kam direkt raus" }
'
