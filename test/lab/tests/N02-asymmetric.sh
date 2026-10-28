ID=N02
TITLE="Asymmetrischer Abbruch: Tunnel-Antworten kommen nicht mehr an (T21)"
EXPECT_CANARY=any
NOTE="Das Gateway verwirft nur Pakete vom Tunnel-Server zum Client. Erwartung: weiterhin alles gesperrt, kein Klartext-Ausweichen (nach Portal-Pruefung wie D01)."
ALLOW=(dst:151.101.1.91:80/tcp)
during() {
	sleep 5
	ep=$(gw head -1 /etc/shuntlab/endpoints); ip=${ep%%:*}
	gw nft add table inet n02
	gw nft "add chain inet n02 f { type filter hook forward priority -10; }"
	gw nft add rule inet n02 f ip saddr "$ip" drop
	sleep 25
	gw nft delete table inet n02
}
CLIENT='
for i in $(seq 25); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 1
done
true
'
