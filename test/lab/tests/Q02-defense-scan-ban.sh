ID=Q02
TITLE="Abwehr: Portscan aus dem Netz -> Ereignis + Sperre (nft shunt_defense)"
CONFIG=defense
EXPECT_CANARY=any
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="Der Scan kommt von einer zweiten Adresse der Gateway-VM (die Gateway-Adresse selbst steht auf der Nie-sperren-Liste, sonst wuerde das Lab sich aussperren). Erwartet: Ereignis scan, Eintrag in /v1/defense bans, Adresse im nft-Set ban4. Endadresse .${DEFENSE_ALT_LAST:-250} im LAN-/24 der VM, aus local.env anpassbar. Nicht in der Lab-VM gelaufen (Stand 11.11.)."
during() {
	sleep 8
	local gwaddr alt
	gwaddr=$(gw ip -4 -o addr show dev enp0s8 | awk '{print $4; exit}')
	alt=${gwaddr%.*}.${DEFENSE_ALT_LAST:-250}
	gw ip addr add "$alt/${gwaddr#*/}" dev enp0s8 2>/dev/null || true
	echo "scan source: secondary address of the gateway VM"
	gw nmap -Pn -sS -S "$alt" -e enp0s8 -p 1-40,80,445,3389 --min-rate 500 "$(gw labctl client | awk '{print $2}')" >/dev/null 2>&1 || true
	echo "$alt" >/tmp/q02-alt.$$
}
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 30
st=$(api /v1/defense)
echo "$st" | grep -o "\"counts\":{[^}]*}"
echo "$st" | grep -q "\"kind\":\"scan\"\|\"scan\":" || api "/v1/defense/events?since=0" | grep -q "\"kind\":\"scan\"" || echo "FAIL kein scan-Ereignis"
echo "$st" | grep -q "\"bans\":\[{" || echo "FAIL keine Sperre in /v1/defense"
sudo -n nft list set inet shunt_defense ban4 | grep -q "elements" || echo "FAIL ban4 leer"
sudo -n nft list ruleset | grep -q "table inet shunt_defense" || echo "FAIL Tabelle shunt_defense fehlt"
true
'
