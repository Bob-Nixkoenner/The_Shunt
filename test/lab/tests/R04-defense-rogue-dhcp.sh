ID=R04
TITLE="Abwehr: Zweiter DHCP-Server im Lab-LAN -> Ereignis dhcp"
CONFIG=defense
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_CANARY=none
NOTE="shunt-kali faehrt attacker/rogue-dhcp.sh (dnsmasq als zweiter DHCP-Server) im Netz
shuntlab. Erwartet: Ereignis kind=dhcp (zweiter Server erkannt), Heat steigt leicht. Die
Pool-Adressen fuer den Rogue-Server kommen aus local.env-Variablen (DEFENSE_POOL_*), nicht aus
dieser Datei. Braucht kali()-Helfer (TODO). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	kali_sync || true
	kali attacker/observer.sh start || true
	: "${DEFENSE_POOL_START:?set DEFENSE_POOL_START/END/ROUTER in local.env (pool outside the real one)}"
	kali env "POOL_START=$DEFENSE_POOL_START" "POOL_END=${DEFENSE_POOL_END:?}" "POOL_ROUTER=${DEFENSE_POOL_ROUTER:?}" DURATION=15 attacker/rogue-dhcp.sh || true
	sleep 2
	kali attacker/observer.sh stop >/tmp/r04-observer.$$ 2>&1 || true
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 25
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"rogue_dhcp\"" || echo "FAIL kein DHCP-Ereignis"
echo "Beobachter sah: $(cat /tmp/r04-observer.* 2>/dev/null | tail -5)"
true
'
