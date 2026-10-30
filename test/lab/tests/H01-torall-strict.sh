ID=H01
TITLE="tor-all: nur tor erreicht Relays, alle anderen Apps nur durch Tor, Tor-Ausfall faellt nicht auf direkt"
CONFIG=tor-all
EXPECT_CANARY=any
ALLOW=(comm:tor)
NOTE="Gateway darf nur Pakete des Prozesses tor sehen. Vor tor-all laeuft tor einmal an (Konsens). Dann: Web ueber Tor (IsTor), direktes UDP/ICMP/anderes Ziel scheitert, tor wird beendet (kein Rueckfall), shuntd wird gestoppt (Tabelle bleibt)."
CLIENT='
tor_ready() { for i in $(seq 90); do [ "$(LANG=C LC_ALL=C sudo -n shunt tor status 2>/dev/null | grep -Ec "connected|verbunden")" -ge 1 ] && return 0; sleep 2; done; return 1; }
istor() { labfree -s -m20 https://check.torproject.org/api/ip 2>/dev/null | grep -q "\"IsTor\":true"; }
tor_ready || echo "FAIL tor kam nicht hoch (ohne tor-all)"
sudo -n shunt tor-all on || echo "FAIL tor-all on abgelehnt"
sleep 3
sudo -n nft list table inet shunt_emerg >/dev/null 2>&1 || echo "FAIL Tabelle shunt_emerg fehlt"
istor || echo "FAIL Web geht nicht durch Tor"
labfree-dig +time=2 +tries=1 @10.77.0.1 "$1" >/dev/null 2>&1 && echo "FAIL DNS an das Gateway beantwortet"
ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo "FAIL ICMP raus"
# 1.1.1.1 per TCP geht legitim durch Tor; direkt ist es erst nach Tor-Ausfall
# tor stirbt: nichts faellt auf direkt
sudo -n pkill -x tor; sleep 1
labfree -s -m4 -o /dev/null http://1.1.1.1/ && echo "FAIL direkt nach Tor-Ausfall (1.1.1.1)"
labfree -s -m4 -o /dev/null "http://$1/" && echo "FAIL Canary nach Tor-Ausfall erreichbar"
# shuntd gestoppt: Tabelle bleibt
sudo -n systemctl stop shuntd; sleep 1
labfree -s -m4 -o /dev/null http://1.1.1.1/ && echo "FAIL direkt ohne shuntd"
sudo -n nft list table inet shunt_emerg >/dev/null 2>&1 || echo "FAIL Tabelle weg nach shuntd-Stopp"
sudo -n systemctl start shuntd; sleep 5
tor_ready || echo "FAIL tor kam nach Neustart nicht wieder hoch"
istor || echo "FAIL nach Neustart kein Tor-Weg"
sudo -n shunt tor-all off; sleep 3
sudo -n nft list table inet shunt_emerg >/dev/null 2>&1 && echo "FAIL Tabelle nach tor-all off noch da"
true
'
