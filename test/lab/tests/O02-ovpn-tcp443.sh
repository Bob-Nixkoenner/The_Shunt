ID=O02
TITLE="OpenVPN ueber TCP/443 im Netz, das nur 80/443 durchlaesst: Tunnel geht, nichts daneben"
CONFIG=ovpn-tcp
MODE=portsonly
ALLOW=(dst:192.168.250.130:443/tcp)
ENDPOINTS=(192.168.250.130:443/tcp) # not in LAB_ENDPOINTS (UDP only): counts as tunnel transport
EXIT_IF=tun1
EXIT_NET=10.168.0.
NOTE="Wie E07, aber der Tunnel ist OpenVPN ueber TCP 443 (CT130, Instanz intern-tcp, tun1). Das Netz laesst nur 80/443 durch: Der Tunnel muss hochkommen und die Tunnel-App ueber ihn rausgehen; sichtbar sein darf nur TCP/443 zum Endpunkt. Aufruf: CT130_IF=tun1 TUNNEL_IP=10.168.0."
CLIENT='
sleep 20
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == 198.51.100.230 ]] || echo "FAIL Tunnel-App nicht ueber den Tunnel (Ausgangs-IP $ip)"
labtun -s -m5 -o /dev/null "http://$1/" || true
ip2=$(labfree -s -m8 http://ifconfig.me/ip); [[ $ip2 == 198.51.100.230 ]] || echo "FAIL App ohne Regel nicht ueber den Tunnel (Ausgangs-IP $ip2)"
true
'
