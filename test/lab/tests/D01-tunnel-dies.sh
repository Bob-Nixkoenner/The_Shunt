ID=D01
TITLE="Tunnel fällt mitten im Betrieb aus: nichts im Klartext"
EXPECT_CANARY=any
NOTE="Nach 6 s schaltet das Gateway den Tunnel-Server weg (Modus tunnelkill)."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
for i in $(seq 12); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 1
done
sudo -n shunt status | sed -n 4,6p
true
'
