ID=M04
TITLE="Tunnel kommt nie hoch (falscher Endpunkt, falscher Schluessel): nie direkt"
CONFIG=m-broken
EXPECT_CANARY=none
PREP='
sudo -n bash -c "cd /etc/shunt/tunnels; sed \"s/^Endpoint *=.*/Endpoint = 192.0.2.77:51820/\" intern.conf >dead.conf; k=\$(wg genkey | wg pubkey); sed \"s|^PublicKey *=.*|PublicKey = \$k|\" intern.conf >badkey.conf; chmod 600 dead.conf badkey.conf"
install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog
'
NOTE="labtun-Regel zeigt auf einen Tunnel mit totem Endpunkt, labtog auf einen mit falschem Schluessel. Erwartung: blockiert, im Status als Fehler sichtbar, nichts im Klartext."
CLIENT='
sleep 4
for i in $(seq 8); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labtun kam durch (toter Tunnel)"
  labtog -s -m2 -o /dev/null "http://t$i-$1/" && echo "FAIL labtog kam durch (falscher Schluessel)"
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
st=$(sudo -n shunt status 2>&1); echo "$st"
gq() { grep -q "$@" <<<"$st"; }
gq -i -E "dead.*(down|error|fail|no handshake|-)" || echo "FAIL Status zeigt den toten Tunnel nicht als Fehler"
true
'
