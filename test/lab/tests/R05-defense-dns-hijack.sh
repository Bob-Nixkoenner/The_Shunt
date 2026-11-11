kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ID=R05
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"TITLE="Abwehr: DNS-Umleitung im Lab-LAN -> Ereignis dns"
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
tail -n 15 "$out/observer.txt"NOTE="shunt-kali faehrt attacker/dns-hijack.sh (ARP-Spoof + eigener DNS-Server, antwortet auf
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"jede Anfrage mit einer fremden Adresse). Erwartet: Ereignis kind=dns_hijack (Gateway-MAC-Wechsel loest sofort eine neue DNS-Pruefung aus, sonst alle 5 min),
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Canary-Abgleich schlaegt an falls der Client eine Kanarien-Domain abfragt. Braucht
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
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
tail -n 15 "$out/observer.txt"	kali env "TARGET=$(client_ip)" "FAKE_IP=${DEFENSE_FAKE_IP:?set DEFENSE_FAKE_IP in local.env}" DURATION=40 attacker/dns-hijack.sh || true
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
tail -n 15 "$out/observer.txt"sleep 50
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api "/v1/defense/events?since=0" | grep -q "\"kind\":\"dns_hijack\"" || echo "FAIL kein DNS-Ereignis"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "Beobachter sah: $(cat /tmp/r05-observer.* 2>/dev/null | tail -5)"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"'
