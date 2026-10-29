ID=B01
TITLE="Tunnel-App fragt ausdrücklich den DNS des fremden Netzes"
EXPECT_CANARY=any
NOTE="Erwartung: die Anfrage an 10.77.0.1 landet nie im Klartext am Gateway (umgeleitet oder durch den Tunnel). Windows: Resolve-DnsName -Server."
CLIENT='
Resolve-DnsName -Name $c -Server 10.77.0.1 -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
Resolve-DnsName -Name "tcp-$c" -Server 10.77.0.1 -Type A -DnsOnly -TcpOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
'
