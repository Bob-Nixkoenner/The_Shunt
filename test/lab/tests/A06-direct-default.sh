ID=A06
TITLE="Standardweg direkt: Tunnel-App bleibt trotzdem im Tunnel"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:185.125.190.0/24:123/udp dst:10.77.0.1:80/tcp) # default route direct: Ubuntu's connectivity check may go direct
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Tunnel-App: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Tunnel-App kam als $ip raus"
# same public IP as the tunnel exit: the gateway is only reachable directly
labfree -s -m4 -o /dev/null http://10.77.0.1/ || echo "FAIL App ohne Regel ging in den Tunnel (Lab-Gateway nicht erreichbar)"
labtun -s -m3 -o /dev/null http://10.77.0.1/ && echo "FAIL Tunnel-App erreicht das Lab-Gateway direkt"
'
