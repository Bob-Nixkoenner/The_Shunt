ID=Q01
TITLE="Abwehr: Koeder lauschen im oeffentlichen Netz, nicht im vertrauten"
CONFIG=defense
EXPECT_CANARY=any
# the defense's active DNS check (dns_probe = on in configs/defense.toml) asks these two fixed names
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
# the decoys are meant to be found
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="Unbekanntes Netz = public: shuntd lauscht auf den Koederports. Danach wird das Netz per [[network]] class=trusted (Gateway-MAC zur Laufzeit aus der Nachbartabelle, nichts davon in der Datei) vertraut: die Koeder muessen weg, ein Zugriff auf sie darf nicht mehr antworten. Nicht in der Lab-VM gelaufen (Stand 11.11.)."
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 6
dec=$(api /v1/defense | grep -o "\"decoys\":\[[^]]*\]")
echo "public: $dec"
for p in 23 80 445 3389; do
	sudo -n ss -Htlnp "sport = :$p" | grep -q shuntd || echo "FAIL Koeder $p lauscht nicht (public)"
done
# trust this network: its gateway MAC, read here, never written to any repo file
gwip=$(ip -4 route show default | awk "{print \$3; exit}")
gwmac=$(ip -4 neigh show "$gwip" | awk "{print \$5; exit}")
[ -n "$gwmac" ] || { echo "FAIL keine Gateway-MAC gefunden"; exit 0; }
sudo -n cp /etc/shunt/shunt.toml /tmp/q01-shunt.toml.bak
printf "\n[[network]]\nname = \"labtrust\"\ngateway_mac = [\"%s\"]\ndefault_route = \"tunnel:intern\"\nclass = \"trusted\"\n" "$gwmac" | sudo -n tee -a /etc/shunt/shunt.toml >/dev/null
sudo -n systemctl reload shuntd; sleep 6
api /v1/defense | grep -o "\"class\":\"[a-z]*\""
for p in 23 80 445 3389; do
	sudo -n ss -Htlnp "sport = :$p" | grep -q shuntd && echo "FAIL Koeder $p lauscht im vertrauten Netz"
done
sudo -n cp /tmp/q01-shunt.toml.bak /etc/shunt/shunt.toml; sudo -n systemctl reload shuntd
true
'
