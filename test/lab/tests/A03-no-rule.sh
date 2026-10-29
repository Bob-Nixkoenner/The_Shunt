ID=A03
TITLE="App ohne Regel nimmt den Standardweg (Tunnel)"
CLIENT='
labfree -s -m8 -o /dev/null "http://$1/" || true
ip=$(labfree -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Ausgangs-IP $ip statt CT130"
'
