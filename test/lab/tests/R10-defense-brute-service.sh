ID=R10
TITLE="Abwehr: Brute Force auf einen echten Dienst (sshd 22) -> brute_service + Sperre, Gegenproben still"
CONFIG=defense-service
EXPECT_CANARY=any
# the defense's active DNS check (dns_probe = on) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_OPEN=("22/tcp" "23/tcp" "80/tcp" "445/tcp" "2222/tcp" "2323/tcp" "3389/tcp")
NOTE="shunt-kali faehrt attacker/brute-service.sh gegen den ECHTEN sshd des Clients (Port 22, kein Koeder;
Konfig defense-service: ohne Inbound-Schutz, damit 22 im Port-Monitor offen ist). Ablauf: erst die
Gegenproben (6 kurze Verbindungen in 10 s wie ein Web-Client; eine 40 s offene Verbindung mit 3 Neuaufbauten
wie Syncthing) -> der Client prueft: kein brute_service. Dann Angriff (hydra -t 16, sonst 4x brute.py ssh) 40 s ->
erwartet brute_service mit handshake=yes, Stufe hoch (ab 60/min) und eine Sperre (nur hoch sperrt) mit reason brute_service. Abgleich ueber Marker-Dateien
im Client (/tmp/r10-*). Der Dienst selbst wird nicht angefasst. Nicht in der Lab-VM gelaufen (Stand 13.11.)."
during() {
	sleep 8
	kali_sync || true
	local t
	t=$(client_ip)
	kali env "TARGET=$t" attacker/brute-service.sh controls || true
	client 'touch /tmp/r10-controls-done'
	# wait until the client has checked the controls (max 90 s)
	for _ in $(seq 45); do client 'test -f /tmp/r10-checked' && break; sleep 2; done
	kali env "TARGET=$t" DURATION=40 attacker/brute-service.sh attack || true
	client 'touch /tmp/r10-attack-done'
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
count() { api "/v1/defense/events?since=0" | grep -o "\"kind\":\"brute_service\"" | wc -l; }
rm -f /tmp/r10-controls-done /tmp/r10-checked /tmp/r10-attack-done
# start clean: a ban of the attacker from an earlier test would swallow everything
sudo -n curl -s --unix-socket /run/shunt/shuntd.sock -X POST -d "{\"src\":\"\"}" http://shunt/v1/defense/unban >/dev/null
shunt ports 2>/dev/null | grep -E "(^|[^0-9])22([^0-9]|$)" | head -3
for i in $(seq 90); do [ -f /tmp/r10-controls-done ] && break; sleep 2; done
[ -f /tmp/r10-controls-done ] || echo "FAIL Gegenproben nicht fertig geworden (Kali?)"
sleep 3
c0=$(count); echo "after controls: brute_service=$c0"
[ "$c0" -eq 0 ] || echo "FAIL Gegenprobe loeste brute_service aus ($c0)"
touch /tmp/r10-checked
for i in $(seq 60); do [ -f /tmp/r10-attack-done ] && break; sleep 2; done
sleep 3
ev=$(api "/v1/defense/events?since=0")
c1=$(count); echo "after attack: brute_service=$c1"
echo "$ev" | grep -o "\"kind\":\"brute_service\"[^}]*" | head -3
[ "$c1" -ge 1 ] || echo "FAIL kein brute_service-Ereignis nach dem Angriff"
echo "$ev" | grep -o "\"kind\":\"brute_service\"[^}]*" | grep -q "handshake=yes" || echo "FAIL brute_service ohne handshake=yes (conntrack lesbar?)"
st=$(api /v1/defense)
echo "$st" | grep -o "\"counts\":{[^}]*}"
echo "$st" | grep -o "\"bans\":\[[^]]*\]" | grep -q "brute_service" || echo "FAIL keine Sperre mit reason brute_service"
systemctl is-active -q sshd 2>/dev/null || systemctl is-active -q ssh || echo "FAIL sshd laeuft nicht mehr (darf nie angefasst werden)"
true
'
