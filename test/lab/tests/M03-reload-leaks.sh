ID=M03
TITLE="Umbau-Lecks: reload und Dienst-Neustart waehrend Apps senden"
EXPECT_CANARY=any
NOTE="Waehrend labtun/labfree dauernd senden: fuenfmal shunt reload, dreimal Neustart von shuntd, einmal Tunnel-Dienst. Kein Paket darf direkt raus (labfree hat Standardweg Tunnel)."
during() {
	sleep 4
	for i in 1 2 3 4 5; do client 'sudo -n shunt reload' || true; sleep 1.5; done
	for i in 1 2 3; do client 'sudo -n systemctl restart shuntd' || true; sleep 3; done
}
CLIENT='
for i in $(seq 50); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labfree-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 0.5
done
true
'
