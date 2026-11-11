ID=R06
TITLE="Abwehr: Fester Beacon + DNS-Tunnel-Muster -> Ereignisse beacon/dns_tunnel"
CONFIG=defense
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_CANARY=none
NOTE="Client faehrt (inline, wie attacker/beacon.sh) 12 kurze Verbindungen im festen 18-s-Takt zu einer Adresse ausserhalb des
Tunnels und (wie attacker/dnstunnel.sh) (lange, zufaellige Subdomains) selbst aus, um die
Eigenbeobachtung (nicht die Lab-Kanten) zu pruefen. Erwartet: Ereignisse kind=beacon und
kind=dns_tunnel in /v1/defense/events, Heat steigt. Beobachter (Kali) laeuft parallel; seine Zusammenfassung steht im Bericht unter Pruefung nebenher.
Nicht in der Lab-VM gelaufen (Stand 11.11.)."
# 12 short connections (curl -m 2) in a fixed 18 s pace: only the connection log
# (NFLOG 5303) sees them, the 10 s socket poll could not
BEACON_COUNT=12
BEACON_GAP=18
during() {
	# the observer lives on Kali (attacker/ is copied there by kali_sync); the client script
	# runs in the VM and cannot read files on the laptop, so the summary is collected here
	# and lands in during.log ("Pruefung nebenher") of the report
	sleep 8
	kali_sync || true
	kali attacker/observer.sh start || true
	# beacon (12 x 18 s) + 15 dig lookups + 15 s wait + margin
	sleep $((BEACON_COUNT * BEACON_GAP + 90))
	kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
	echo "Beobachter sah:"
	tail -n 15 "$out/observer.txt"
}
CLIENT="BEACON_DEST=${DEFENSE_BEACON_DEST:?set DEFENSE_BEACON_DEST in local.env} TUNNEL_DOMAIN=${DEFENSE_TUNNEL_DOMAIN:?set DEFENSE_TUNNEL_DOMAIN in local.env}"'
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
# the attack runs inline: no files to copy (PREP runs in the client, where client_cp_to does not exist)
for i in $(seq '$BEACON_COUNT'); do curl -s -m 2 "http://$BEACON_DEST/" -o /dev/null || true; sleep '$BEACON_GAP'; done
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
