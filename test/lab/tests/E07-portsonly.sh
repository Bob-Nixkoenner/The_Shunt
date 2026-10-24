ID=E07
TITLE="Gäste-WLAN lässt nur 80/443 durch (Tunnel-UDP gesperrt)"
MODE=portsonly
EXPECT_CANARY=none
CLIENT='
sleep 5
labtun -s -m5 -o /dev/null "http://$1/" && echo "FAIL Tunnel-App kam raus, obwohl der Tunnel gesperrt ist"
labfree -s -m5 -o /dev/null https://example.com/ && echo "FAIL App ohne Regel kam direkt raus"
true
'
