ID=R02
TITLE="Abwehr: Brute-Force auf Koeder-SSH/Telnet -> Ereignis + Sperre"
CONFIG=defense
EXPECT_CANARY=any
EXPECT_OPEN=("23/tcp" "2222/tcp" "2323/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="shunt-kali faehrt attacker/brute-telnet-ssh.sh gegen die Koederports des Clients
(ssh 2222 bzw. 22, telnet 23 bzw. 2323; Port 22 gehoert auf dem Testclient einem echten sshd).
Erwartet: Ereignisse kind=cowrie (ssh + telnet, nie das Passwort), kind=brute_force, Heat steigt staerker als beim Portscan (mehr
Verbindungen pro Zeit), baldige Sperre. Braucht den gleichen kali()-Helfer wie R01 (TODO in
lab.sh). Nicht in der Lab-VM gelaufen (Stand 11.11.). Koeder-Ports 2222/2323 stehen im nft-Set decoy_ports
(der Daemon traegt alle lauschenden Koeder ein, defensePushPorts)."
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
echo "$st" | grep -o "\"heat\":[0-9]*"
ev=$(api "/v1/defense/events?since=0")
echo "$ev" | grep -o "ssh login user=[^\"]*" | head -1 | grep -q "len=" || echo "FAIL kein cowrie-Ereignis fuer ssh"
echo "$ev" | grep -o "telnet login user=[^\"]*" | head -1 | grep -q "len=" || echo "FAIL kein cowrie-Ereignis fuer telnet"
echo "$st" | grep -q "\"heat\":0[,}]" && echo "FAIL Heat steigt nicht"
# the event is the proof; the ban may already be gone again (ban_seconds)
api "/v1/defense/events?since=0" | grep -q "\"kind\":\"brute_force\"" || echo "FAIL kein brute_force-Ereignis"
echo "$st" | grep -q "\"bans\":\[{" || echo "FAIL keine aktive Sperre in /v1/defense"
echo "Beobachter sah: $(cat /tmp/r02-observer.* 2>/dev/null | tail -5)"
true
'
