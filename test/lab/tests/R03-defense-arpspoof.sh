ID=R03
TITLE="Abwehr: ARP-Spoof auf die Gateway-Adresse -> Ereignis gateway_mismatch"
CONFIG=defense
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_CANARY=none
NOTE="shunt-kali faehrt attacker/arpspoof.sh und beansprucht die Gateway-MAC gegenueber dem
Client. Erwartet: Ereignis kind=arp bzw. gateway_mismatch (Gateway-MAC weicht von der bei
Netzbeitritt gemerkten ab), Heat steigt deutlich, Netz bleibt/wird public, keine Herabstufung
zu trusted. Braucht kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	kali_sync || true
	kali attacker/observer.sh start || true
	kali env "TARGET=$(client_ip)" DURATION=15 attacker/arpspoof.sh || true
	sleep 2
	kali attacker/observer.sh stop >/tmp/r03-observer.$$ 2>&1 || true
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 25
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"arp\"\|\"kind\":\"gateway_mismatch\"" || echo "FAIL kein ARP-Ereignis"
api /v1/defense | grep -o "\"class\":\"[a-z]*\""
echo "Beobachter sah: $(cat /tmp/r03-observer.* 2>/dev/null | tail -5)"
true
'
