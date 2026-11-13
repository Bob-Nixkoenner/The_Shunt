ID=MH01
TITLE="Multi-Hop WG in WG: das fremde Netz sieht nur den aeusseren Tunnel"
CONFIG=hop
NOTE="Lab-Apps auf tunnel:hop (CT130 wgt1) ueber tunnel:intern (wgt0). Mitschnitt CT130 mit CT130_IF=wgt1 TUNNEL_IP=@LAB_NET_HOP@<n>. Gateway darf nur CT130:51830 sehen; :51831 am Gateway = innerer Hop am aeusseren vorbei."
CLIENT='
sleep 6
for i in $(seq 5); do labtun -s -m3 -o /dev/null "http://$i-$1/"; labtun-dig +time=2 +tries=1 "d$i-$1" >/dev/null; sleep 1; done
labtun -s -m5 http://@LAB_HOP_SRV@/ | grep -q "tunnel=@LAB_HOP_SRV@" || echo "FAIL Testseite des inneren Hops nicht erreicht"
sudo -n shunt status --json | grep -q "\"via\": *\"tunnel:intern\"" || echo "FAIL Status zeigt den Hop nicht"
true
'
