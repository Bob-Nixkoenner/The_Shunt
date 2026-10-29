ID=D04
TITLE="Netz verbindet neu (DHCP) während Apps senden"
EXPECT_CANARY=any
during() { sleep 4; renew_client; }
CLIENT='
for i in $(seq 15); do labtun -s -m2 -o /dev/null "http://$i-$1/"; labfree -s -m2 -o /dev/null http://1.1.1.1/; sleep 0.7; done
true
'
