ID=R08
TITLE="Abwehr: TLS-Pruefung, Ausstellerwechsel (Test-CA A -> B) -> Ereignis tls (high)"
CONFIG=defense-tls
# no DNS probe in defense-tls.toml; the lab name is resolved through /etc/hosts, no query leaves the client
ALLOW=(comm:shuntd)
EXPECT_CANARY=none
TLS_LAB_NAME=shunt-tls.lab.test
NOTE="Kali spielt zuerst den Server mit Zertifikat von Test-CA A (attacker/tlsmitm.sh), dann denselben Namen
mit Zertifikat von Test-CA B (Abfang-Ersatz: Kali als MITM, ohne echten Proxy). Der Client kennt beide CAs
(Systemspeicher), damit die Kette prueft und nur der Ausstellerwechsel zaehlt. Erstpin: in der Lab-LAN
(Klasse public, kein Internet fuer den zweiten Weg/DoH) wird nicht selbst gepinnt; der Test legt den Pin
von CA A in tlspins.json (0600) ab. Der echte Erstpin ueber trusted/zweiten Weg ist NICHT abgedeckt (braucht
ein [[network]]-Profil bzw. Internet; eigener Test noetig). Der Pruefdurchlauf startet 20 s nach shuntd-Start:
der Test startet shuntd neu (kein Ausloeser per API). Phase 1 (CA A): kein tls-Ereignis. Phase 2 (CA B):
tls/high 'issuer chain differs'. Annahme: Zustandsordner /var/lib/shunt/defense oder per find ermittelt.
Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	local n=$TLS_LAB_NAME kip=${KALI_IP:?KALI_IP}
	sleep 6
	kali_sync || true
	kali env "TLSDIR=/root/tlsmitm" attacker/tlsmitm.sh init "$n"
	for ca in a b; do # trust both test CAs on the client (system store) so the chain verifies
		b=$(kali base64 -w0 /root/tlsmitm/ca-$ca.pem) # client() has no stdin: pass the PEM as base64 text
		client "echo $b | base64 -d | sudo -n tee /usr/local/share/ca-certificates/shuntlab-r08-$ca.crt >/dev/null"
	done
	client "sudo -n update-ca-certificates >/dev/null 2>&1; sudo -n sed -i '/ $n\$/d' /etc/hosts; echo '$kip $n' | sudo -n tee -a /etc/hosts >/dev/null"
	local fp b
	fp=$(kali env TLSDIR=/root/tlsmitm attacker/tlsmitm.sh fp a | tail -1)
	kali env TLSDIR=/root/tlsmitm attacker/tlsmitm.sh serve a "$n"
	client "d=\$(sudo -n find /var/lib/shunt -name tlspins.json 2>/dev/null | head -1 | xargs -r dirname); d=\${d:-/var/lib/shunt/defense}; sudo -n mkdir -p \$d; echo '{\"$n\":[\"$fp\"]}' | sudo -n tee \$d/tlspins.json >/dev/null; sudo -n chmod 600 \$d/tlspins.json; sudo -n systemctl restart shuntd"
	sleep 40
	client "touch /tmp/r08-phase1"
	kali env TLSDIR=/root/tlsmitm attacker/tlsmitm.sh serve b "$n"
	client "sudo -n systemctl restart shuntd"
	sleep 40
	client "touch /tmp/r08-phase2"
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
rm -f /tmp/r08-phase1 /tmp/r08-phase2
w() { for i in $(seq 200); do [ -e "$1" ] && return 0; sleep 2; done; return 1; }
w /tmp/r08-phase1 || echo "FAIL Phase 1 nicht fertig"
ev=$(api "/v1/defense/events?since=0")
echo "$ev" | grep -q "\"kind\":\"tls\"" && echo "FAIL tls-Ereignis schon mit Zertifikat von CA A"
w /tmp/r08-phase2 || echo "FAIL Phase 2 nicht fertig"
ev=$(api "/v1/defense/events?since=0")
echo "$ev" | grep -q "\"kind\":\"tls\"" || echo "FAIL kein tls-Ereignis nach Wechsel auf CA B"
echo "$ev" | grep -o "{[^{}]*\"kind\":\"tls\"[^{}]*}" | grep -q "\"severity\":3" || echo "FAIL tls-Ereignis nicht High"
echo "$ev" | grep -q "differs" || echo "FAIL Text issuer chain differs fehlt"
true
'
after() {
	kali env TLSDIR=/root/tlsmitm attacker/tlsmitm.sh stop || true
	client "sudo -n rm -f /usr/local/share/ca-certificates/shuntlab-r08-*.crt /tmp/r08-phase*; sudo -n update-ca-certificates --fresh >/dev/null 2>&1; sudo -n sed -i '/ $TLS_LAB_NAME\$/d' /etc/hosts" || true
}
