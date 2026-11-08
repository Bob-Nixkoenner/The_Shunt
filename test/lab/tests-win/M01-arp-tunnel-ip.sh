ID=M01
TITLE="ARP nach Tunnel- und Adapter-IP: antwortet der Client im fremden Netz?"
EXPECT_CANARY=any
NOTE="Das Gateway fragt per arping nach der Tunnel-IP (TUNNEL_IP, lebt nur im Userspace-Kern) und nach der Adresse des Shunt-Adapters (10.111.0.2). Eine Antwort auf der Ethernet-Karte verraet 'nutzt VPN' (Windows nutzt normalerweise das strenge Host-Modell, erwartet: keine Antwort). Rein vom Gateway gemessen, kein Prozess-Trace noetig."
during() {
	sleep 3
	local ip
	for ip in "$TUNNEL_IP" 10.111.0.2; do
		if gw arping -c 4 -w 8 -I enp0s8 "$ip" >/tmp/m01-arping.$$ 2>&1; then
			echo "FAIL Client beantwortet ARP nach $ip im fremden Netz"
		fi
		cat /tmp/m01-arping.$$; rm -f /tmp/m01-arping.$$
	done
}
CLIENT='Start-Sleep 24'
