ID=G01
TITLE="Portscan aus dem fremden Netz"
SCAN=1
EXPECT_CANARY=any
NOTE="nmap vom Gateway: TCP alle Ports, UDP Top 200, IPv4 + IPv6 link-local."
CLIENT='sleep 5; sudo -n ss -Htulnp | grep -v "127.0.0\|\[::1\]" | sed "s/^/lauscht: /"; true'
