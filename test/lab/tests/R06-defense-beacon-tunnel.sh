ID=R06
TITLE="Abwehr: Fester Beacon + DNS-Tunnel-Muster -> Ereignisse beacon/dnstunnel"
CONFIG=defense
EXPECT_CANARY=none
NOTE="Client faehrt attacker/beacon.sh (festes Intervall zu einer Adresse ausserhalb des
Tunnels) und attacker/dnstunnel.sh (lange, zufaellige Subdomains) selbst aus, um die
Eigenbeobachtung (nicht die Lab-Kanten) zu pruefen. Erwartet: Ereignisse kind=beacon und
kind=dnstunnel in /v1/defense/events, Heat steigt. Beobachter beobachtet parallel am Gateway.
Nicht in der Lab-VM gelaufen (Stand 11.11.)."
PREP='
client_cp_to "$HERE/attacker/beacon.sh" /tmp/shuntlab-attacker
client_cp_to "$HERE/attacker/dnstunnel.sh" /tmp/shuntlab-attacker
client_cp_to "$HERE/attacker/common.sh" /tmp/shuntlab-attacker
'
during() {
	sleep 8
	gw attacker/observer.sh start || true
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
chmod +x /tmp/shuntlab-attacker/*.sh
DEST="${DEFENSE_BEACON_DEST:?}" INTERVAL=5 COUNT=6 /tmp/shuntlab-attacker/beacon.sh || true
DOMAIN="${DEFENSE_TUNNEL_DOMAIN:?}" COUNT=15 /tmp/shuntlab-attacker/dnstunnel.sh || true
sleep 15
st=$(api "/v1/defense/events?since=0")
echo "$st" | grep -q "\"kind\":\"beacon\"" || echo "FAIL kein Beacon-Ereignis"
echo "$st" | grep -q "\"kind\":\"dnstunnel\"" || echo "FAIL kein DNS-Tunnel-Ereignis"
true
'
after() {
	gw attacker/observer.sh stop
}
