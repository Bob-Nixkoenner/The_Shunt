ID=MH03
TITLE="Multi-Hop: innerer Tunnel kommt nie hoch (falscher Schluessel): kein Rueckfall auf den ersten Hop"
CONFIG=hop
HOP_BADKEY=1
EXPECT_CANARY=none
NOTE="hop.conf mit falschem Server-Schluessel. Die App auf tunnel:hop bekommt nichts; der Canary darf weder im Klartext noch auf wgt0 (Rueckfall auf Hop A) noch am Gateway erscheinen. Aufruf: CT130_IF=wgt0 lab.sh run MH03"
CLIENT='
sleep 6
for i in $(seq 8); do labtun -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labtun kam durch (innerer Hop tot)"; labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null; sleep 1; done
st=$(sudo -n shunt status 2>&1); echo "$st"
if grep -E "^hop .* ok " <<<"$st" >/dev/null; then echo "FAIL Status zeigt den Hop ohne Handshake als ok"; fi
true
'
