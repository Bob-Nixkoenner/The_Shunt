ID=A11
TITLE="Start-Wettlauf ohne Halten (Standardstufe): unsichere Regeln werden markiert, keine Fehlstarts"
CONFIG=race-mark
EXPECT_CANARY=tunnel
ALLOW=(comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:140.211.169.0/24:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp dst:10.77.0.1:80/tcp comm:apt comm:http comm:NetworkManager comm:isahc-agent comm:systemd-timesyn comm:systemd-timesyncd net:185.199.108.0/22:443/tcp net:2606:50c0::/32:443/tcp host:.pop-os.org:80/tcp host:api.pop-os.org:443/tcp host:.fedoraproject.org:80/tcp)
NOTE="Wie A10, aber Standardstufe: der Startschutz setzt die Marke der ersten passenden App-Regel statt zu halten (Bob 09.11.). Erwartung: kein Paket von labtun* am Lab-Gateway, labtun scheitert hoechstens 1-2x (nicht 40/40 wie mit Halten), start_guard.marked > 0, held = 0."
CLIENT='
fail=0; ok=0; freefail=0
for i in $(seq 40); do
  if labtun -s -m3 -o /dev/null "http://c$i-$1/"; then ok=$((ok+1)); else fail=$((fail+1)); fi
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null 2>&1
  labfree -s -m3 -o /dev/null http://10.77.0.1/ || freefail=$((freefail+1))
done
echo "labtun ok=$ok fehlgeschlagen=$fail; labfree (direkt, kein Argument) fehlgeschlagen=$freefail"
(( freefail > 4 )) && echo "FAIL labfree ohne Argument scheitert zu oft ($freefail/40)"
(( fail > 4 )) && echo "FAIL labtun scheitert zu oft ($fail/40): haelt statt zu markieren?"
st=$(sudo -n shunt status --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"start_guard\"))" 2>/dev/null)
echo "start_guard: $st"
true
'
