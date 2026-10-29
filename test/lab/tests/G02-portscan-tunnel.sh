ID=G02
TITLE="Erreichbar über die Tunnel-Adresse (von CT130 aus)"
EXPECT_CANARY=any
NOTE="CT130 klopft an häufige Ports von 10.66.0.12 an. Offen = FAIL."
during() {
	sleep 2
	ct130 'for p in 22 53 80 443 631 1716 5353 8080 8731 22000; do timeout 2 bash -c "echo > /dev/tcp/10.66.0.12/$p" 2>/dev/null && echo "FAIL Port $p/tcp über den Tunnel erreichbar" || echo "zu: $p/tcp"; done'
}
CLIENT='sleep 30'
