ID=A10
TITLE="Start-Wettlauf mit Halten: unsichere Regeln blockieren kurz statt Standardweg"
CONFIG=race-hold
EXPECT_CANARY=tunnel
ALLOW=(comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:140.211.169.0/24:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp dst:10.77.0.1:80/tcp)
NOTE="Eine Domain-Regel steht vor der App-Regel, labfree hat eine Argument-Regel: der Startschutz kann keine Marke setzen und hält die Sockets an (EPERM), bis appwatch entschieden hat. Erwartung: kein Paket von labtun* am Lab-Gateway, einzelne Fehlstarts erlaubt (Zahl im Bericht), labfree ohne Argument geht direkt und scheitert höchstens 1-2x."
CLIENT='
fail=0; ok=0; freefail=0
for i in $(seq 40); do
  if labtun -s -m3 -o /dev/null "http://c$i-$1/"; then ok=$((ok+1)); else fail=$((fail+1)); fi
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null 2>&1
  labfree -s -m3 -o /dev/null http://10.77.0.1/ || freefail=$((freefail+1))
done
echo "labtun ok=$ok fehlgeschlagen=$fail; labfree (direkt, kein Argument) fehlgeschlagen=$freefail"
(( freefail > 4 )) && echo "FAIL labfree ohne Argument scheitert zu oft ($freefail/40): Halten zu lang"
st=$(sudo -n shunt status --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"start_guard\"))" 2>/dev/null)
echo "start_guard: $st"
true
'
