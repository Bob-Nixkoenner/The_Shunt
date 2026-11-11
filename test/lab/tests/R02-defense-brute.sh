ID=R02
TITLE="Abwehr: Brute-Force auf Koeder-SSH/Telnet -> Ereignis + Sperre"
CONFIG=defense
EXPECT_CANARY=any
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="shunt-kali faehrt attacker/brute-telnet-ssh.sh gegen die Koederports 22/23 des Clients.
Erwartet: Ereignis kind=auth bzw. brute, Heat steigt staerker als beim Portscan (mehr
Verbindungen pro Zeit), baldige Sperre. Braucht den gleichen kali()-Helfer wie R01 (TODO in
lab.sh). Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	kali attacker/observer.sh start || true
	kali env "TARGET=$(client_ip)" DURATION=20 attacker/brute-telnet-ssh.sh || true
	sleep 2
	kali attacker/observer.sh stop >/tmp/r02-observer.$$ 2>&1 || true
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
# start clean: a ban of the attacker left from R01 would swallow the whole attack
sudo -n curl -s --unix-socket /run/shunt/shuntd.sock -X POST -d "{\"src\":\"\"}" http://shunt/v1/defense/unban >/dev/null
sleep 40
st=$(api /v1/defense)
echo "$st" | grep -o "\"counts\":{[^}]*}"
# the event is the proof; the ban may already be gone again (ban_seconds)
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"brute_force\"" || echo "FAIL kein brute_force-Ereignis"
echo "$st" | grep -q "\"bans\":\[{" || echo "FAIL keine aktive Sperre in /v1/defense"
echo "Beobachter sah: $(cat /tmp/r02-observer.* 2>/dev/null | tail -5)"
true
'
