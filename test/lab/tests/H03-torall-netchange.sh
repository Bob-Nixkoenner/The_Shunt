ID=H03
TITLE="tor-all x Netzwechsel: DHCP-Erneuerung waehrend Apps senden, nie direkt"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
during() { sleep 12; renew_client; }
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -c "connected")" -ge 1 ] && return 0; sleep 2; done; return 1; }
istor() { labfree -s -m20 https://check.torproject.org/api/ip 2>/dev/null | grep -q "\"IsTor\":true"; }
tor_ready || echo "FAIL tor kam nicht hoch"
sudo -n shunt tor-all on || echo "FAIL tor-all on"
sleep 2
for i in $(seq 25); do
	labfree -s -m2 -o /dev/null http://1.1.1.1/ && echo "FAIL direkt waehrend Netzwechsel (1.1.1.1)"
	labfree -s -m2 -o /dev/null "http://$i-$1/" && echo "FAIL Canary direkt waehrend Netzwechsel"
	sleep 0.7
done
for i in $(seq 20); do istor && break; sleep 3; done
istor || echo "FAIL nach Netzwechsel kein Tor-Weg"
sudo -n shunt tor-all off; sleep 2
true
'
