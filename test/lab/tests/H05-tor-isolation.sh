ID=H05
TITLE="Tor-Isolation: zwei Apps bekommen verschiedene Exits"
CONFIG=tor-app
EXPECT_CANARY=any
ALLOW=(comm:tor comm:chronyd comm:NetworkManager comm:snapd comm:systemd-timesyn comm:pacman dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp)
NOTE="labtun und labdir laufen ueber Tor in zwei Regeln (isolate = app, Standard: eigene Kreise pro Regel). Ihre Exit-IPs (check.torproject.org/api/ip) muessen sich unterscheiden; drei Versuche, weil zwei Kreise zufaellig denselben Exit haben koennen."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
ip() { "$1" -s -m20 https://check.torproject.org/api/ip | sed -n "s/.*\"IP\":\"\([^\"]*\)\".*/\1/p"; }
tor_ready || echo "FAIL tor kam nicht hoch"
ok=0
for i in 1 2 3; do a=$(ip labtun); b=$(ip labdir); echo "Versuch $i: labtun $a, labdir $b"; [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] && { ok=1; break; }; sleep 5; done
[ $ok = 1 ] || echo "FAIL beide Apps haben denselben Exit (oder keinen)"
true
'
