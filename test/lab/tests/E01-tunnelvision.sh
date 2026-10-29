ID=E01
TITLE="TunnelVision: DHCP Option 121 lenkt Routen am Tunnel vorbei"
MODE=tunnelvision
NOTE="CVE-2024-3661. Das Gateway verteilt 0.0.0.0/1 und 128.0.0.0/1 über sich selbst."
CLIENT='
ip route | head -5
labtun -s -m8 -o /dev/null "http://$1/" || true
labfree -s -m8 -o /dev/null "http://f-$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Tunnel-App: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Tunnel-App kam als $ip raus"
'
