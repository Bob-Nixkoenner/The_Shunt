ID=R05
TITLE="Abwehr: DNS-Umleitung im Lab-LAN -> Ereignis dns"
CONFIG=defense
EXPECT_CANARY=none
NOTE="shunt-kali faehrt attacker/dns-hijack.sh (ARP-Spoof + eigener DNS-Server, antwortet auf
jede Anfrage mit einer fremden Adresse). Erwartet: Ereignis kind=dns bzw. dns_spoof,
Canary-Abgleich schlaegt an falls der Client eine Kanarien-Domain abfragt. Braucht
kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	kali attacker/observer.sh start || true
	kali "TARGET=\$(gw labctl client | awk '{print \$2}') FAKE_IP=\${DEFENSE_FAKE_IP:?} DURATION=15 attacker/dns-hijack.sh" || true
	sleep 2
	kali attacker/observer.sh stop >/tmp/r05-observer.$$ 2>&1 || true
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 25
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"dns\"" || echo "FAIL kein DNS-Ereignis"
echo "Beobachter sah: $(cat /tmp/r05-observer.* 2>/dev/null | tail -5)"
true
'
