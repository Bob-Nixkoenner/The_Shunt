ID=G02
TITLE="Erreichbar über die Tunnel-Adresse (von CT130 aus)"
EXPECT_CANARY=any
NOTE="CT130 klopft an häufige Ports der Tunnel-Adresse an. Offen = FAIL."
during() {
	sleep 2
	ct130 "for p in 22 53 80 135 139 443 445 3389 5040 5357 7680 8080; do timeout 2 bash -c \"echo > /dev/tcp/$TUNNEL_IP/\$p\" 2>/dev/null && echo \"FAIL Port \$p/tcp über den Tunnel erreichbar\" || echo \"zu: \$p/tcp\"; done"
}
CLIENT='Start-Sleep 30'
