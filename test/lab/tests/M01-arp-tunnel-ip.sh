ID=M01
TITLE="ARP nach der Tunnel-IP: antwortet der Client im fremden Netz?"
EXPECT_CANARY=any
NOTE="Das Gateway fragt per arping nach der Tunnel-IP. Eine Antwort verraet 'nutzt VPN' und die Tunnel-IP (Mullvad setzt arp_ignore)."
during() {
	sleep 3
	if gw arping -c 4 -w 8 -I enp0s8 "$TUNNEL_IP" >/tmp/m01-arping.$$ 2>&1; then
		echo "FAIL Client beantwortet ARP nach der Tunnel-IP $TUNNEL_IP im fremden Netz"
	fi
	cat /tmp/m01-arping.$$; rm -f /tmp/m01-arping.$$
}
CLIENT='sleep 14; true'
