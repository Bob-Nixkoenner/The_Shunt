ID=O03
TITLE="OpenVPN mit falschem tls-crypt-Schluessel / tls-auth statt tls-crypt: Tunnel bleibt unten, nie direkt"
CONFIG=ovpn-variants
EXPECT_CANARY=none
ALLOW=(dst:${CT130_IP}:1194/udp)
PREP='
cat >/tmp/mk.sh <<\EOF2
cd /etc/shunt/tunnels
{ sed "/<tls-crypt>/,/<\/tls-crypt>/d" intern.ovpn; echo "<tls-crypt>"; echo "-----BEGIN OpenVPN Static key V1-----"
  for i in $(seq 16); do head -c16 /dev/urandom | od -An -tx1 | tr -d " \n"; echo; done
  echo "-----END OpenVPN Static key V1-----"; echo "</tls-crypt>"; } >wrongkey.ovpn
sed -e "s|<tls-crypt>|key-direction 1\n<tls-auth>|" -e "s|</tls-crypt>|</tls-auth>|" intern.ovpn >tlsauth.ovpn
chmod 600 wrongkey.ovpn tlsauth.ovpn
EOF2
sudo -n bash /tmp/mk.sh
install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog
'
NOTE="Wie O05, aber der Server ist erreichbar und antwortet nur auf das richtige tls-crypt. labtun zeigt auf einen Tunnel mit zufaelligem tls-crypt-Schluessel, labtog auf einen, der denselben Schluessel als tls-auth statt tls-crypt nutzt. Erwartung: Handshake scheitert, beide bleiben blockiert, nichts im Klartext, Status nie ok."
CLIENT='
sleep 10
for i in $(seq 8); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL labtun kam durch (falscher Schluessel)"
  labtog -s -m2 -o /dev/null "http://t$i-$1/" && echo "FAIL labtog kam durch (tls-auth)"
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
st=$(sudo -n shunt status 2>&1); echo "$st"
if grep -E "^(wrongkey|tlsauth) .* ok " <<<"$st" >/dev/null; then echo "FAIL Status zeigt einen Tunnel ohne Verbindung als ok"; fi
true
'
