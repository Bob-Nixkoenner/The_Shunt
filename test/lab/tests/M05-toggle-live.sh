ID=M05
TITLE="Regel im laufenden Betrieb umschalten: Tunnel -> direkt -> Tunnel"
CONFIG=m-toggle
EXPECT_CANARY=any
ALLOW=(comm:labtog)
PREP='install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog'
NOTE="labtog startet dauernd neu und fragt seine oeffentliche IP ab. Nach jedem reload muss die IP dem neuen Weg folgen (Tunnel = Austritts-IP des Test-Servers, direkt = IP des Gateways/Hosts). Kurze Gnadenfrist 3 s."
CLIENT='
ip_of() { labtog -s -m4 https://api.ipify.org 2>/dev/null; }
set_route() { sudo -n sed -i "/name = \"lab: toggle\"/,\$ s|^route = .*|route = \"$1\"|" /etc/shunt/shunt.toml; sudo -n shunt reload; sleep 3; }
T1=$(ip_of); echo "tunnel: $T1"
[ -n "$T1" ] || echo "FAIL keine IP im Tunnel-Zustand"
for round in 1 2; do
  set_route direct; D=$(ip_of); echo "direct: $D"
  [ -n "$D" ] && [ "$D" != "$T1" ] || echo "FAIL nach direct: IP $D (Tunnel $T1), Regel greift nicht"
  set_route tunnel:intern; T2=$(ip_of); echo "tunnel: $T2"
  [ "$T2" = "$T1" ] || echo "FAIL zurueck auf Tunnel: IP $T2 statt $T1"
done
true
'
