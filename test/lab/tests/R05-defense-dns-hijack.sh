ID=R05
TITLE="Abwehr: DNS-Umleitung im Lab-LAN -> Ereignis dns"
CONFIG=defense
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_CANARY=none
NOTE="shunt-kali faehrt attacker/dns-hijack.sh (ARP-Spoof + eigener DNS-Server, antwortet auf
jede Anfrage mit einer fremden Adresse). Erwartet: Ereignis kind=dns_hijack (Gateway-MAC-Wechsel loest sofort eine neue DNS-Pruefung aus, sonst alle 5 min),
Canary-Abgleich schlaegt an falls der Client eine Kanarien-Domain abfragt. Braucht
kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	kali_sync || true
	kali attacker/observer.sh start || true
	kali env "TARGET=$(client_ip)" "FAKE_IP=${DEFENSE_FAKE_IP:?set DEFENSE_FAKE_IP in local.env}" DURATION=40 attacker/dns-hijack.sh || true
	sleep 2
	kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
	echo "Beobachter sah:"
	tail -n 15 "$out/observer.txt"
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 50
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"dns_hijack\"" || echo "FAIL kein DNS-Ereignis"
true
'
