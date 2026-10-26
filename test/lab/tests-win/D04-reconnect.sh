ID=D04
TITLE="Netz verbindet neu (DHCP) während Apps senden"
EXPECT_CANARY=any
during() { sleep 4; renew_client; }
CLIENT='
1..15 | ForEach-Object { & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"; & C:\lab\labfree.exe -s -m2 -o NUL http://1.1.1.1/; Start-Sleep -Milliseconds 700 }
'
