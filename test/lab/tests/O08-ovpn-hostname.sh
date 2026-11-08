ID=O08
TITLE="OpenVPN-Endpunkt als Hostname (statt IP): Tunnel geht, nichts im Klartext"
CONFIG=ovpn-host
ALLOW=(dst:192.168.222.130:1194/udp)
PREP='
cat >/tmp/mk.sh <<\EOF2
grep -q ct130.shuntlab.test /etc/hosts || echo "192.168.222.130 ct130.shuntlab.test" >>/etc/hosts
cd /etc/shunt/tunnels
sed "s/^remote .*/remote ct130.shuntlab.test 1194/" intern.ovpn >host.ovpn
chmod 600 host.ovpn
EOF2
sudo -n bash /tmp/mk.sh
'
EXIT_IF=tun0
EXIT_NET=10.67.0.
NOTE="Der remote-Eintrag der .ovpn ist ein Hostname (ueber /etc/hosts aufgeloest, im Lab sieht man dafuer keine DNS-Anfrage). Erwartung: Tunnel kommt hoch, Tunnel-App geht ueber CT130, nichts im Klartext. Aufruf: CT130_IF=tun0 TUNNEL_IP=10.67.0."
CLIENT='
sleep 10
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Tunnel-App nicht ueber den Tunnel (Ausgangs-IP $ip)"
labtun -s -m5 -o /dev/null "http://$1/" || true
true
'
