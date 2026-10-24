ID=A06
TITLE="Standardweg direkt: Tunnel-App bleibt trotzdem im Tunnel"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns)
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Tunnel-App: $ip"
[[ $ip == 198.51.100.230 ]] || echo "FAIL Tunnel-App kam als $ip raus"
ip=$(labfree -4 -s -m8 http://ifconfig.me/ip); echo "App ohne Regel: $ip"
[[ $ip != 198.51.100.230 ]] || echo "FAIL App ohne Regel ging in den Tunnel"
'
