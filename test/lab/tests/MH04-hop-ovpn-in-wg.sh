ID=MH04
TITLE="Multi-Hop OpenVPN in WireGuard: das fremde Netz sieht nur WireGuard"
CONFIG=hop-ovpn
NOTE="OpenVPN-Hop (remote 10.66.0.1 1194, hop.ovpn) ueber den WireGuard-Tunnel intern. Gateway sieht nur CT130:51830/udp. Mitschnitt CT130_IF=tun0 TUNNEL_IP=<Adresse im 10.67er Netz>."
CLIENT='
sleep 10
for i in $(seq 5); do labtun -s -m4 -o /dev/null "http://$i-$1/"; labtun-dig +time=2 +tries=1 "d$i-$1" >/dev/null; sleep 1; done
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ -n $ip ]] || echo "FAIL Tunnel-App ueber den OpenVPN-Hop ohne Antwort"
sudo -n shunt status --json | grep -q "\"via\": *\"tunnel:intern\"" || echo "FAIL Status zeigt den Hop nicht"
true
'
