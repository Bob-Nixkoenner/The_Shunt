ID=H08
TITLE=".onion-Namen gehen nie an einen normalen DNS-Server"
CONFIG=tor-app
EXPECT_CANARY=none
ALLOW=(comm:tor comm:chronyd comm:NetworkManager comm:snapd comm:systemd-timesyn comm:pacman dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp)
NOTE="Die Canary wird als <canary>.onion gefragt: von einer direkten App (labfree), einer Tor-App (labtun) und per getent. Sie darf weder am Gateway (DNS) noch am Tunnel-Ausgang auftauchen."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam nicht hoch"
o="$1.onion"
labfree-dig +time=3 +tries=1 "$o" A >/dev/null 2>&1
labtun-dig +time=3 +tries=1 "$o" A >/dev/null 2>&1
getent hosts "$o" >/dev/null 2>&1
labfree -s -m6 -o /dev/null "http://$o/" 2>/dev/null
true
'
