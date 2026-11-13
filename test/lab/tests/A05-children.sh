ID=A05
TITLE="Kindprozesse erben den Tunnel"
CLIENT='
labtun-sh -c "curl -s -m8 -o /dev/null http://$1/; (sleep 1; curl -s -m8 http://ifconfig.me/ip > /tmp/a05.ip) & wait"
ip=$(cat /tmp/a05.ip); echo "Ausgangs-IP Enkel: $ip"
[[ $ip == @LAB_EXIT_IP@ ]] || echo "FAIL Kindprozess kam als $ip raus"
'
