kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ID=R03
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"TITLE="Abwehr: ARP-Spoof auf die Gateway-Adresse -> Ereignis gateway_mismatch"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"CONFIG=defense
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"EXPECT_CANARY=none
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"NOTE="shunt-kali faehrt attacker/arpspoof.sh und beansprucht die Gateway-MAC gegenueber dem
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Client. Erwartet: Ereignis kind=arp bzw. gateway_mismatch (Gateway-MAC weicht von der bei
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Netzbeitritt gemerkten ab), Heat steigt deutlich, Netz bleibt/wird public, keine Herabstufung
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"zu trusted. Braucht kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"during() {
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	sleep 8
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali_sync || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali attacker/observer.sh start || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali env "TARGET=$(client_ip)" DURATION=15 attacker/arpspoof.sh || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	sleep 2
	kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
	echo "Beobachter sah:"
	tail -n 15 "$out/observer.txt"|| true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"}
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"CLIENT='
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"sleep 25
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api "/v1/defense/events?since=0" | grep -q "\"kind\":\"arp\"\|\"kind\":\"gateway_mismatch\"" || echo "FAIL kein ARP-Ereignis"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api /v1/defense | grep -o "\"class\":\"[a-z]*\""
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "Beobachter sah: $(cat /tmp/r03-observer.* 2>/dev/null | tail -5)"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"'
