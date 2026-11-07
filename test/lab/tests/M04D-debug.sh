ID=M04D
TITLE="(Debug) Tunnel kommt nie hoch (falscher Endpunkt, falscher Schluessel): nie direkt"
CONFIG=m-broken
EXPECT_CANARY=none
ALLOW=(dst:192.0.2.77:51820/udp)
PREP='
sudo -n bash -c "cd /etc/shunt/tunnels; sed \"s/^Endpoint *=.*/Endpoint = 192.0.2.77:51820/\" intern.conf >dead.conf; k=\$(wg genkey | wg pubkey); sed \"s|^PublicKey *=.*|PublicKey = \$k|\" intern.conf >badkey.conf; chmod 600 dead.conf badkey.conf"
install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog
'
NOTE="labtun-Regel zeigt auf einen Tunnel mit totem Endpunkt, labtog auf einen mit falschem Schluessel. Erwartung: blockiert, im Status als Fehler sichtbar, nichts im Klartext."
CLIENT='
sudo -n bash -c "(tcpdump -l -n -tt -i sh-intern udp port 53 2>/dev/null | sed -u \"s/^/INTERN /\" > /tmp/m04-intern.txt &) ; (tcpdump -l -n -tt -i sh-dead udp port 53 2>/dev/null | sed -u \"s/^/DEAD /\" > /tmp/m04-dead.txt &)"
date +%s.%N | sed "s/^/START /"
sleep 4
for i in $(seq 8); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labtun kam durch (toter Tunnel)"
  labtog -s -m2 -o /dev/null "http://t$i-$1/" && echo "FAIL labtog kam durch (falscher Schluessel)"
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
date +%s.%N | sed "s/^/ENDE /"
sleep 3; sudo -n pkill tcpdump; sudo -n cat /tmp/m04-intern.txt /tmp/m04-dead.txt | cut -c1-150
sudo -n journalctl -u shuntd --since "-3min" --no-pager -o short-unix 2>/dev/null | grep -i "dns\|dead\|tunnel\|watchdog\|resync" | tail -25 | cut -c1-200
st=$(sudo -n shunt status 2>&1); echo "$st"
if grep -E "^(dead|badkey) .* ok " <<<"$st" >/dev/null; then echo "FAIL Status zeigt einen Tunnel ohne Handshake als ok"; fi
true
'
