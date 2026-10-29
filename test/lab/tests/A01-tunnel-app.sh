ID=A01
TITLE="App auf dem Tunnel geht nur über CT130 raus"
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Ausgangs-IP $ip statt 185.216.213.230 (CT130)"
'
