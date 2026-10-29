ID=G04
TITLE="Tunnel weg: auch NTP, QUIC, Ping, DNS bleiben gesperrt"
MODE=tunnelkill
EXPECT_CANARY=none
CLIENT='
sleep 3
echo x | labtun-nc -u -w1 162.159.200.1 123
echo x | labtun-nc -u -w1 1.1.1.1 443
echo x | labfree-nc -u -w1 1.1.1.1 443
labtun-dig +time=2 +tries=1 @9.9.9.9 "$1" >/dev/null
ping -c2 -W1 1.1.1.1 >/dev/null && echo "FAIL Ping ging raus, obwohl der Tunnel weg ist"
sudo -n ping -c2 -W1 9.9.9.9 >/dev/null && echo "FAIL Ping (root) ging raus"
true
'
