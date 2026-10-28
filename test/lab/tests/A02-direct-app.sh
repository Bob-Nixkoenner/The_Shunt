ID=A02
TITLE="App auf direkt geht am Tunnel vorbei"
EXPECT_CANARY=gw
ALLOW=(comm:labdir dns)
NOTE="Direkt heißt: das fremde Netz darf diese App und ihre DNS-Anfragen sehen."
CLIENT='
labdir -s -m8 -o /dev/null "http://$1/" || true
# the lab host and CT130 share one public IP: tell the way by the gateway, which only a direct app can reach
labdir -s -m4 -o /dev/null http://10.77.0.1/ || echo "FAIL direkte App erreicht das Lab-Gateway nicht (kam über den Tunnel raus)"
'
