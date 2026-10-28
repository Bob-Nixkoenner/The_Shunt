ID=N01
TITLE="Fremde Firewall-Manipulation: nft flush ruleset waehrend Apps senden (T18)"
EXPECT_CANARY=any
NOTE="Ein anderes Programm (Docker, fremdes VPN, Nutzer) leert alle nft-Regeln. Erwartung ohne Soll-Ist-Abgleich: Leck bis zum naechsten Reload (Fund). Mit Abgleich: Regeln kommen zurueck, hoechstens kurzes Fenster."
during() { sleep 5; client 'sudo -n nft flush ruleset'; sleep 20; }
CLIENT='
for i in $(seq 30); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labfree-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 1
done
sudo -n nft list tables | grep -q "inet shunt" || echo "FAIL Tabelle inet shunt fehlt nach 30 s noch immer"
true
'
