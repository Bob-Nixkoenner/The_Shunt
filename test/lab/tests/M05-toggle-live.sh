ID=M05
TITLE="Regel im laufenden Betrieb umschalten: Tunnel -> direkt -> Tunnel"
CONFIG=m-toggle
EXPECT_CANARY=any
ALLOW=(comm:labtog)
PREP='install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog'
NOTE="labtog startet dauernd neu und fragt das Lab-Gateway (10.77.0.1, nur direkt erreichbar) ab. Nach jedem reload muss der Weg der Regel folgen. Kurze Gnadenfrist 3 s."
CLIENT='
# direct = the lab gateway is reachable (a private address cannot be reached through the tunnel)
ip_of() { if labtog -s -m3 -o /dev/null http://10.77.0.1/; then echo direct; else echo tunnel; fi; }
set_route() { sudo -n sed -i "/name = \"lab: toggle\"/,\$ s|^route = .*|route = \"$1\"|" /etc/shunt/shunt.toml; sudo -n shunt reload; sleep 3; }
T1=$(ip_of); echo "tunnel: $T1"
[ "$T1" = tunnel ] || echo "FAIL Ausgangszustand nicht Tunnel: $T1"
for round in 1 2; do
  set_route direct; D=$(ip_of); echo "direct: $D"
  [ "$D" = direct ] || echo "FAIL nach direct: Weg $D, Regel greift nicht"
  set_route tunnel:intern; T2=$(ip_of); echo "tunnel: $T2"
  [ "$T2" = tunnel ] || echo "FAIL zurueck auf Tunnel: Weg $T2"
done
true
'
