kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ID=R02
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"TITLE="Abwehr: Brute-Force auf Koeder-SSH/Telnet -> Ereignis + Sperre"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"CONFIG=defense
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"EXPECT_CANARY=any
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"EXPECT_OPEN=("23/tcp" "2222/tcp" "2323/tcp" "80/tcp" "445/tcp" "3389/tcp")
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"NOTE="shunt-kali faehrt attacker/brute-telnet-ssh.sh (python3 brute.py, kein Hydra mehr - Hydra
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"haengt sich an der korrekten Telnet-IAC-Verhandlung des Koeders auf) gegen die Koederports des
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Clients (ssh 2222 bzw. 22, telnet 23 bzw. 2323; Port 22 gehoert auf dem Testclient einem echten
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"sshd). N=10 Versuche je Dienst (env N=... fuer brute-telnet-ssh.sh).
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"Erwartet: >= N/2 kind=cowrie Ereignisse, Heat > 0, baldige Sperre. Braucht den gleichen
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"kali()-Helfer wie R01 (TODO in lab.sh). Nicht in der Lab-VM gelaufen (Stand 11.11.). Koeder-Ports
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"2222/2323 stehen im nft-Set decoy_ports (der Daemon traegt alle lauschenden Koeder ein,
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"defensePushPorts)."
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"during() {
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	sleep 8
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali_sync || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali attacker/observer.sh start || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	kali env "TARGET=$(client_ip)" DURATION=30 N=10 attacker/brute-telnet-ssh.sh || true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"	sleep 2
	kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
	echo "Beobachter sah:"
	tail -n 15 "$out/observer.txt"|| true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"}
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"CLIENT='
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"# start clean: a ban of the attacker left from R01 would swallow the whole attack
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"sudo -n curl -s --unix-socket /run/shunt/shuntd.sock -X POST -d "{\"src\":\"\"}" http://shunt/v1/defense/unban >/dev/null
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"sleep 40
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"st=$(api /v1/defense)
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "$st" | grep -o "\"counts\":{[^}]*}"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "$st" | grep -o "\"heat\":[0-9]*"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"ev=$(api "/v1/defense/events?since=0")
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"cowrie_n=$(echo "$ev" | grep -o "\"kind\":\"cowrie\"" | wc -l)
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "cowrie_events=$cowrie_n"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"[ "$cowrie_n" -ge 5 ] || echo "FAIL zu wenige cowrie-Ereignisse ($cowrie_n, erwartet >= 5 bei N=10)"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "$st" | grep -q "\"heat\":0[,}]" && echo "FAIL Heat steigt nicht"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "$ev" | grep -q "\"kind\":\"brute_force\"" || echo "FAIL kein brute_force-Ereignis"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "$st" | grep -q "\"bans\":\[{" || echo "FAIL keine aktive Sperre in /v1/defense"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"echo "Beobachter sah: $(cat /tmp/r02-observer.* 2>/dev/null | tail -5)"
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"true
kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
echo "Beobachter sah:"
tail -n 15 "$out/observer.txt"'
