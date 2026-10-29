ID=B01
TITLE="Tunnel-App fragt ausdrücklich den DNS des fremden Netzes"
EXPECT_CANARY=any
NOTE="Erwartung: die Anfrage an 10.77.0.1 landet nie im Klartext am Gateway (umgeleitet oder durch den Tunnel)."
CLIENT='
labtun-dig +time=3 +tries=1 @10.77.0.1 "$1" A || true
labtun-dig +time=3 +tries=1 @10.77.0.1 "tcp-$1" A +tcp || true
'
