ID=E06
TITLE="Captive Portal: alles hängt am Portal"
MODE=captive
EXPECT_CANARY=none
ALLOW=(comm:shuntd dns)
NOTE="shuntd darf seine Portal-Erkennung (HTTP, direkt) machen. Tunnel-Apps dürfen nichts im Klartext senden."
CLIENT='
sleep 8; sudo -n shunt status | sed -n 1,3p
labtun -s -m5 -o /dev/null "http://$1/" && echo "FAIL Tunnel-App kam trotz Portal raus"
labfree -s -m5 -o /dev/null "http://f-$1/"
true
'
