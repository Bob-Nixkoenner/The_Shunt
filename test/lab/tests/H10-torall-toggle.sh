ID=H10
TITLE="tor-all: mehrfach an/aus, direkt nach 'on' ist kein Weg am Tor vorbei offen"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
NOTE="Fuenfmal on/off. Gleich nach jedem 'on' (ohne Wartezeit) darf der Canary (nur ueber das Gateway erreichbar) und ein UDP-Ziel nicht durchkommen; Tabelle shunt_emerg ist da. Nach 'off' ist sie weg."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
tor_ready || echo "FAIL tor kam nicht hoch"
for i in 1 2 3 4 5; do
	sudo -n shunt tor-all on >/dev/null || echo "FAIL on $i abgelehnt"
	echo "LABMARK strict_from $(date +%s.%N)"
	labfree -s -m3 -o /dev/null "http://$i-$1/" && echo "FAIL Canary direkt gleich nach on ($i)"
	[ -n "$(labfree-dig +short +time=1 +tries=1 @10.77.0.1 "q$i-$1" 2>/dev/null)" ] && echo "FAIL DNS ans Gateway gleich nach on ($i)"
	sudo -n nft list table inet shunt_emerg >/dev/null 2>&1 || echo "FAIL Tabelle fehlt nach on ($i)"
	echo "LABMARK strict_until $(date +%s.%N)"
	sudo -n shunt tor-all off >/dev/null
	sudo -n nft list table inet shunt_emerg >/dev/null 2>&1 && echo "FAIL Tabelle nach off noch da ($i)"
	sleep 1
done
true
'
