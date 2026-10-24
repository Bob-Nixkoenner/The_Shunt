ID=A02
TITLE="App auf direkt geht am Tunnel vorbei"
EXPECT_CANARY=gw
ALLOW=(comm:labdir dns)
NOTE="Direkt heißt: das fremde Netz darf diese App und ihre DNS-Anfragen sehen."
CLIENT='
labdir -s -m8 -o /dev/null "http://$1/" || true
ip=$(labdir -4 -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip != 185.216.213.230 && -n $ip ]] || echo "FAIL direkte App kam über den Tunnel raus ($ip)"
'
