ID=A09
TITLE="Start-Wettlauf: frisch gestartete Tunnel-App, erster Socket sofort nach exec, nie direkt"
CONFIG=direct
EXPECT_CANARY=tunnel
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:140.211.169.0/24:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp comm:apt comm:http comm:NetworkManager comm:isahc-agent comm:systemd-timesyn comm:systemd-timesyncd net:185.199.108.0/22:443/tcp net:2606:50c0::/32:443/tcp host:.pop-os.org:80/tcp host:api.pop-os.org:443/tcp) # default route direct: connectivity check and NTP of the distro
NOTE="Standardweg direkt, labtun*/labtun-dig in den Tunnel. Jede Runde ein neuer Prozess, der sofort nach exec einen Socket öffnet (dig: aus einem eigenen Thread; labtun-sh: Kind vor dem Verschieben). Erwartung: kein Paket von labtun* am Lab-Gateway; shunt status --json zeigt start_guard.marked > 0. Ohne eBPF-Startschutz (Warnung in shunt check) ist ein Fund hier erwartet."
CLIENT='
for i in $(seq 40); do
  labtun-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  labtun -s -m2 -o /dev/null "http://c$i-$1/"
  labtun-sh -c "exec dig +time=1 +tries=1 s$i-$1 >/dev/null"
  labtun-sh -c "dig +time=1 +tries=1 k$i-$1 >/dev/null & wait"
done
st=$(sudo -n shunt status --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"start_guard\"))" 2>/dev/null)
echo "start_guard: $st"
[[ $st == None || -z $st ]] && echo "FAIL eBPF-Startschutz nicht geladen (shunt check)"
true
'
