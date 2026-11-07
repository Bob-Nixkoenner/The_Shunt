ID=MH08
TITLE="Multi-Hop live umbauen: via entfernen und wieder setzen, nichts im Klartext"
CONFIG=hop
EXPECT_CANARY=any
ALLOW=(comm:labtog)
PREP='install -m755 /usr/bin/curl /tmp/labtog && sudo -n install -m755 /tmp/labtog /usr/local/bin/labtog'
NOTE="labtog (Regel auf tunnel:hop) fragt dauernd eine Seite. Zwischendurch wird das via des Hops aus der Config genommen und wieder gesetzt (reload). In der Luecke darf nichts im Klartext und kein Paket zu :51831 am Gateway auftauchen; danach muss der Hop wieder tragen."
CLIENT='
hop_ok() { labtog -s -m4 http://10.69.0.1/ | grep -q "tunnel=10.69.0.1"; }
set_via() { sudo -n sed -i "/^\[tunnel.hop\]/,/^\[\[rule\]\]/ s|^via = .*|$1|" /etc/shunt/shunt.toml; sudo -n shunt reload; sleep 4; }
sleep 6; hop_ok || echo "FAIL Ausgangszustand: Hop traegt nicht"
for round in 1 2; do
  set_via "# via entfernt"
  for i in 1 2 3; do labtog -s -m2 -o /dev/null "http://l$round$i-$1/" || true; done
  set_via "via = \"tunnel:intern\""; sleep 4
  hop_ok || echo "FAIL Runde $round: Hop traegt nach dem Zurueckschalten nicht"
done
true
'
