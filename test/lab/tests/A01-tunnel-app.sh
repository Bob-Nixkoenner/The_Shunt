ID=A01
TITLE="App auf dem Tunnel geht nur über CT130 raus"
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == @LAB_EXIT_IP@ ]] || echo "FAIL Ausgangs-IP $ip statt @LAB_EXIT_IP@ (CT130)"
'
