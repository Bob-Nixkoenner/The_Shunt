kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ID=R04
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"TITLE="Abwehr: Zweiter DHCP-Server im Lab-LAN -> Ereignis dhcp"
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
tail -n 15 "$out/observer.txt"NOTE="shunt-kali faehrt attacker/rogue-dhcp.sh (dnsmasq als zweiter DHCP-Server) im Netz
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"shuntlab. Erwartet: Ereignis kind=dhcp (zweiter Server erkannt), Heat steigt leicht. Die
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Pool-Adressen fuer den Rogue-Server kommen aus local.env-Variablen (DEFENSE_POOL_*), nicht aus
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"dieser Datei. Braucht kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
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
tail -n 15 "$out/observer.txt"	: "${DEFENSE_POOL_START:?set DEFENSE_POOL_START/END/ROUTER in local.env (pool outside the real one)}"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali env "POOL_START=$DEFENSE_POOL_START" "POOL_END=${DEFENSE_POOL_END:?}" "POOL_ROUTER=${DEFENSE_POOL_ROUTER:?}" DURATION=45 attacker/rogue-dhcp.sh || true
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
tail -n 15 "$out/observer.txt"sleep 20
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"# the one-off 4 s probe after joining came before the rogue server: restart shuntd now,
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"# so the probe runs again while the rogue server answers (it runs for 45 s)
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"sudo -n systemctl restart shuntd; sleep 12
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api "/v1/defense/events?since=0" | grep -q "\"kind\":\"rogue_dhcp\"" || echo "FAIL kein DHCP-Ereignis"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "Beobachter sah: $(cat /tmp/r04-observer.* 2>/dev/null | tail -5)"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"'
