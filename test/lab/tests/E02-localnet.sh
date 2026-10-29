ID=E02
TITLE="TunnelCrack LocalNet: das Netz gibt sich als 1.1.1.0/24 aus"
MODE=localnet
NOTE="Der Tunnel-DNS 1.1.1.1 liegt jetzt scheinbar im lokalen Netz. Er darf trotzdem nur durch den Tunnel gefragt werden."
CLIENT='
ip -4 addr show scope global | grep inet
labtun -s -m8 -o /dev/null "http://$1/" || true
labtun -s -m8 -o /dev/null http://1.1.1.1/ || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Tunnel-App: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Tunnel-App kam als $ip raus"
'
