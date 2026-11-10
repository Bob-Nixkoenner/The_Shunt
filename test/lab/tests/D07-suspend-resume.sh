ID=D07
TITLE="Ruhezustand: nach dem Aufwachen geht nichts im Klartext raus"
EXPECT_CANARY=any
ALLOW=(dst:151.101.1.91:80/tcp dst:10.77.0.1:0/icmp)
SETTLE=1
NOTE="Die VM wird per 'controlvm savestate' eingefroren (wie Ruhezustand: alle Sockets bleiben, die Uhr springt, der Handshake laeuft ab), nach 200 s (laenger als die 180 s WireGuard-Sitzung) wieder gestartet. Die App sendet davor und danach. Erlaubt wie bei D01: die Portal-Pruefung von shuntd (direkt); dazu das ICMP 'udp port 68 unreachable' des Kernels an den DHCP-Server, wenn nach dem Aufwachen die DHCP-Antwort kommt (Gateway-Adresse, kein Nutzdatenverkehr). Ohne neuen bpftrace-Lauf nach dem Aufwachen."
during() {
	sleep 8
	VBoxManage controlvm "$CLIENT_VM" savestate
	sleep 200
	VBoxManage startvm "$CLIENT_VM" --type headless >/dev/null
	sleep 20
	wait_for "client after resume" 300 client true
	ip=$(client 'sleep 3; labtun -s -m8 http://ifconfig.me/ip' || true); echo "Ausgangs-IP nach dem Aufwachen: $ip"
	client 'for i in $(seq 25); do labtun -s -m2 -o /dev/null "http://r$i-'"$canary"'/"; labfree -s -m2 -o /dev/null http://1.1.1.1/; sleep 1; done; true' || true
}
CLIENT='
for i in $(seq 6); do labtun -s -m2 -o /dev/null "http://$i-$1/"; labfree -s -m2 -o /dev/null http://1.1.1.1/; sleep 1; done
true
'
