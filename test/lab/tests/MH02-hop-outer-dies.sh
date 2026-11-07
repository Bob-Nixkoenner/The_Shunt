ID=MH02
TITLE="Multi-Hop: aeusserer Tunnel faellt aus, nichts im Klartext"
CONFIG=hop
EXPECT_CANARY=any
ALLOW=(dst:151.101.1.91:80/tcp)
NOTE="Nach 6 s sperrt das Gateway CT130:51830 (tunnelkill). Erlaubt wie D01: Portal-Pruefung von shuntd. Kein Versuch zu :51831 direkt am Gateway."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
for i in $(seq 12); do labtun -s -m2 -o /dev/null "http://$i-$1/"; labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null; sleep 1; done
true
'
