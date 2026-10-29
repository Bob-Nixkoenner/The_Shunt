ID=P03
TITLE="Panik mit panic_kill: Programme im Tunnel werden beendet, Direkt-Programme nicht"
CONFIG=panic-kill
EXPECT_CANARY=any
NOTE="labtun-sh (Tunnel) und labdir-nc (direkt) laufen. shunt panic on beendet die Tunnel-Gruppe, Netz ist zu. panic off hebt die Sperre auf."
CLIENT='
labtun-sh -c "sleep 300; true" & 
labdir-nc -l 127.0.0.1 9009 >/dev/null 2>&1 &
sleep 3
n1=$(pgrep -c -x labtun-sh); n2=$(pgrep -c -x labdir-nc)
sudo -n shunt panic on; sleep 2
pgrep -x labtun-sh >/dev/null && echo "FAIL labtun-sh lebt nach Panik (panic_kill)"
pgrep -x labdir-nc >/dev/null || echo "FAIL labdir-nc wurde mitbeendet"
labfree -s -m2 -o /dev/null http://1.1.1.1/ && echo "FAIL Netz bei Panik offen"
sudo -n shunt panic off; sleep 2
labtun -s -m4 -o /dev/null "http://$1/" || true
pkill -x labdir-nc; pkill -x sleep
true
'
