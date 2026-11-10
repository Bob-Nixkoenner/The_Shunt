ID=F05
TITLE="Tarnung: wiedererkennbar über Netze hinweg (DHCPv6-DUID, Client-ID, MAC)?"
MODE=dhcpv6
CHECKS=(fingerprint per-network)
EXPECT_CANARY=any
SETTLE=1
NOTE="Der Client verbindet nacheinander zwei getrennte NetworkManager-Profile (\"Netz A\", \"Netz B\") auf derselben Karte, das Gateway vergibt IPv6 per DHCPv6. Gleiche DUID, Client-ID oder MAC in beiden = ein Netzbetreiber (oder zwei, die sich austauschen) erkennt das Gerät wieder. Erwartet heute: Fund (tarnung-fremde-netze.md T2/T3)."
CLIENT='
dev=$(nmcli -g DEVICE,TYPE dev | awk -F: "\$2==\"ethernet\"{print \$1; exit}")
orig=$(nmcli -g GENERAL.CONNECTION dev show "$dev")
for n in "Netz A" "Netz B"; do
	sudo -n nmcli con delete "$n" >/dev/null 2>&1 || true
	sudo -n nmcli con add type ethernet ifname "$dev" con-name "$n" ipv6.method auto >/dev/null
	# shuntd may stop this first activation before DHCP (host name) and start it again itself
	if ! sudo -n nmcli -w 30 con up "$n" >/dev/null 2>&1; then
		echo "Hinweis: $n erste Aktivierung abgebrochen (shuntd-Startschutz?)"
		for i in $(seq 20); do nmcli -g GENERAL.STATE con show "$n" 2>/dev/null | grep -q activated && break; sleep 1; done
		nmcli -g GENERAL.STATE con show "$n" 2>/dev/null | grep -q activated || echo "FAIL $n kam nicht hoch"
	fi
	sleep 12
	echo "$n: $(ip -6 addr show dev "$dev" scope global | grep -o "inet6 [^ ]*" | tr "\n" " ")"
done
sudo -n nmcli -w 30 con up "$orig" >/dev/null || true
for n in "Netz A" "Netz B"; do sudo -n nmcli con delete "$n" >/dev/null 2>&1 || true; done
true
'
