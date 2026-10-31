ID=H11
TITLE="Neustart mit aktivem tor-all bleibt dicht (Boot-Leck)"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
SETTLE=1
NOTE="tor-all an, dann Neustart; das Gateway schneidet bis 60 s nach dem Start mit und darf nur tor sehen. Ohne Prozess-Trace nach dem Neustart: was nicht tor zugeordnet werden kann, ist ein Fund. Danach tor-all aus."
during() {
	client 'for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && break; sleep 2; done; sudo -n shunt tor-all on' || echo "FAIL tor-all on"
	echo "LABMARK strict_from $(date +%s.%N)"
	client 'sudo -n systemctl reboot' || true
	sleep 25
	wait_for "client after reboot" 300 client true
	sleep 60
	echo "LABMARK strict_until $(date +%s.%N)"
	client 'sudo -n nft list table inet shunt_emerg >/dev/null 2>&1' || echo "FAIL Notfall-Tabelle nach Neustart weg"
	client 'sudo -n shunt tor-all off >/dev/null 2>&1' || true
	client "sudo -n /usr/local/lib/shuntlab/trace.sh start /tmp/shuntlab-trace.log" # so stop/copy find a file
}
CLIENT='true'
