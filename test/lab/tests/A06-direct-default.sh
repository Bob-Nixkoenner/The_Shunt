ID=A06
TITLE="Standardweg direkt: Tunnel-App bleibt trotzdem im Tunnel"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:140.211.169.0/24:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp dst:10.77.0.1:80/tcp net:185.199.108.0/22:443/tcp comm:NetworkManager comm:apt comm:isahc-agent comm:http comm:systemd-timesyn comm:systemd-timesyncd net:2606:50c0::/32:443/tcp host:.pop-os.org:80/tcp host:api.pop-os.org:443/tcp host:.fedoraproject.org:80/tcp net:2620:52:6::/48:80/tcp net:2600:1f18:568d::/48:80/tcp net:2606:f640:6000::/48:80/tcp net:2600:1f14:fad::/48:80/tcp net:2604:1580:fe00::/48:80/tcp net:2605:bc80:3010::/48:80/tcp) # default route direct: the distro's connectivity check (Ubuntu, Fedora) and NTP may go direct
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Tunnel-App: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Tunnel-App kam als $ip raus"
# same public IP as the tunnel exit: the gateway is only reachable directly
labfree -s -m4 -o /dev/null http://10.77.0.1/ || echo "FAIL App ohne Regel ging in den Tunnel (Lab-Gateway nicht erreichbar)"
labtun -s -m3 -o /dev/null http://10.77.0.1/ && echo "FAIL Tunnel-App erreicht das Lab-Gateway direkt"
'
