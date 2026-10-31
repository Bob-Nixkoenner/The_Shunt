ID=H02
TITLE="tor-all x Panik: nach Panik aus bleibt alles in Tor, nie direkt"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
istor() { for i in 1 2 3; do labfree -s -m20 https://check.torproject.org/api/ip 2>/dev/null | grep -q "\"IsTor\":true" && return 0; sleep 5; done; return 1; } # a fresh circuit after a restart can take a try or two
tor_ready || echo "FAIL tor kam nicht hoch"
sudo -n shunt tor-all on || echo "FAIL tor-all on"
echo "LABMARK strict_from $(date +%s.%N)"
sleep 3
istor || echo "FAIL kein Tor-Weg vor Panik"
sudo -n shunt panic on; sleep 2
istor && echo "FAIL Tor-Weg bei Panik offen"
sudo -n shunt panic off; sleep 2
labfree -s -m4 -o /dev/null "http://$1/" && echo "FAIL Canary direkt nach Panik aus"
for i in $(seq 20); do istor && break; sleep 3; done
istor || echo "FAIL nach Panik aus kein Tor-Weg"
echo "LABMARK strict_until $(date +%s.%N)"
sudo -n shunt tor-all off; sleep 2
true
'
