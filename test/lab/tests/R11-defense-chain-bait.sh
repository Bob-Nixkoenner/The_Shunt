ID=R11
TITLE="Abwehr: Kette in Maschinentempo (Scan -> Koeder-Datei -> Login mit Koeder-Passwort) -> bait + automated_chain + Sperre"
CONFIG=defense-chain
EXPECT_CANARY=any
# the defense's active DNS check (dns_probe = on) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "2222/tcp" "2323/tcp" "3389/tcp")
NOTE="shunt-kali faehrt attacker/chain.sh: nmap -sS 1-1024, sofort curl /.env vom HTTP-Koeder (Port 80),
sofort Login (POST /login) mit dem Passwort aus der Datei. Konfig defense-chain: Scan-Sperre AUS (sonst
schneidet die Scan-Sperre nach dem ersten Handshake die Kette ab), Login-Sperre an, cowrie an.
Erwartet: kind=bait (high), kind=automated_chain (high, via=bait), eine Sperre mit reason bait oder
automated_chain, Detail ohne Passwort. Nicht in der Lab-VM gelaufen (Stand 13.11.)."
during() {
	sleep 8
	kali_sync || true
	kali env "TARGET=$(client_ip)" attacker/chain.sh || true
	client 'touch /tmp/r11-attack-done'
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
rm -f /tmp/r11-attack-done
# start clean: a ban of the attacker from an earlier test would swallow everything
sudo -n curl -s --unix-socket /run/shunt/shuntd.sock -X POST -d "{\"src\":\"\"}" http://shunt/v1/defense/unban >/dev/null
for _ in $(seq 60); do test -f /tmp/r11-attack-done && break; sleep 2; done
sleep 3
ev=$(api "/v1/defense/events?since=0")
st=$(api /v1/defense)
echo "$ev" | grep -o "\"kind\":\"\(bait\|automated_chain\|scan\)\"[^}]*" | head -5
echo "$ev" | grep -q "\"kind\":\"scan\"" || echo "FAIL kein scan-Ereignis"
echo "$ev" | grep -q "\"kind\":\"bait\"" || echo "FAIL kein bait-Ereignis (Koeder-Passwort nicht erkannt)"
echo "$ev" | grep -o "\"kind\":\"automated_chain\"[^}]*" | grep -q "via=bait" || echo "FAIL kein automated_chain mit via=bait"
echo "$st" | grep -o "\"bans\":\[[^]]*\]" | grep -q "\"reason\":\"\(bait\|automated_chain\)\"" || echo "FAIL keine Sperre mit reason bait/automated_chain"
pw=$(sudo -n sed -n "s/.*\"password\":\"\([^\"]*\)\".*/\1/p" /var/lib/shunt/defense/bait.json 2>/dev/null)
[ -n "$pw" ] && echo "$ev" | grep -qF "$pw" && echo "FAIL Koeder-Passwort steht im Ereignis"
true
'
