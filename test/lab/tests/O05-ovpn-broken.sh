ID=O05
TITLE="OpenVPN-Tunnel kommt nie hoch (toter Endpunkt, fehlender tls-crypt-Schluessel): nie direkt"
CONFIG=ovpn-broken
EXPECT_CANARY=none
ALLOW=(dst:192.0.2.77:1194/udp)
PREP='
sudo -n bash -c "cd /etc/shunt/tunnels; sed \"s/^remote .*/remote 192.0.2.77 1194/\" intern.ovpn >dead.ovpn; sed \"/<tls-crypt>/,/<\\/tls-crypt>/d\" intern.ovpn >notc.ovpn; chmod 600 dead.ovpn notc.ovpn"
install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog
'
NOTE="Wie M04, mit OpenVPN: labtun-Regel zeigt auf einen Tunnel mit totem Endpunkt, labtog auf einen, dem der tls-crypt-Schluessel fehlt (der Server antwortet nicht). Erwartung: blockiert, nichts im Klartext, Status nie 'ok'. Die Pakete an das Gateway-Ziel des Servers (1194) sind erlaubt."
CLIENT='
sleep 6
for i in $(seq 8); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labtun kam durch (toter Tunnel)"
  labtog -s -m2 -o /dev/null "http://t$i-$1/" && echo "FAIL labtog kam durch (ohne tls-crypt)"
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
st=$(sudo -n shunt status 2>&1); echo "$st"
if grep -E "^(dead|notc) .* ok " <<<"$st" >/dev/null; then echo "FAIL Status zeigt einen Tunnel ohne Verbindung als ok"; fi
true
'
