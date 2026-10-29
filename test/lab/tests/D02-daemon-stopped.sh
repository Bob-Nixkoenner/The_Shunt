ID=D02
TITLE="shuntd gestoppt: Kill-Switch hält"
EXPECT_CANARY=none
CLIENT='
sudo -n systemctl stop shuntd
labtun -s -m4 -o /dev/null http://1.1.1.1/ && echo "FAIL Tunnel-App kam ohne shuntd raus"
labfree -s -m4 -o /dev/null http://1.1.1.1/ && echo "INFO App ohne Regel kam ohne shuntd raus"
labtun-dig +time=2 +tries=1 @10.77.0.1 "$1" >/dev/null
sudo -n systemctl start shuntd; sleep 4
true
'
