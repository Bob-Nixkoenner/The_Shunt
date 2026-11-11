ID=R01
TITLE="Abwehr: Portscan aus shunt-kali -> Ereignis + Heat + Sperre"
CONFIG=defense
EXPECT_CANARY=any
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="Angreifer: shunt-kali (zweite VM am intnet shuntlab, keine eigene IP im Repo) faehrt
attacker/portscan.sh gegen die Client-Adresse. Noch kein kali()-Helfer in lab.sh: dieser Test
braucht einen Aufruf analog zu gw() auf dem Kali-Host (siehe test/lab/attacker/README-Stub,
TODO). Erwartet: Ereignis kind=scan in /v1/defense/events, Heat steigt, bei genug Traffic ein
Eintrag in bans + nft-Set ban4. Beobachter (observer.sh) laeuft parallel, Gegenprobe in der
Ausgabe. Nicht in der Lab-VM gelaufen (Stand 11.11., Kali-Installation lief noch)."
during() {
	sleep 8
	kali_sync || true
	kali attacker/observer.sh start || true
	kali env "TARGET=$(client_ip)" PORTS=1-1024 attacker/portscan.sh || true
	sleep 2
	kali attacker/observer.sh stop >"$out/observer.txt" 2>&1 || true
	echo "Beobachter sah:"
	tail -n 15 "$out/observer.txt"
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 30
st=$(api /v1/defense)
echo "$st" | grep -o "\"counts\":{[^}]*}"
echo "$st" | grep -q "\"kind\":\"scan\"" || api "/v1/defense/events?since=0" | grep -q "\"kind\":\"scan\"" || echo "FAIL kein scan-Ereignis"
true
'
