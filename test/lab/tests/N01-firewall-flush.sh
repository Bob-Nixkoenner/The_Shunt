ID=N01
TITLE="Fremde Firewall-Manipulation: nft flush ruleset waehrend Apps senden (T18)"
EXPECT_CANARY=any
# The guard polls once a second, so right after the flush there is a window of up to ~1 s
# in which the apps send in the clear: that is allowed here (ALLOW), what counts is
# how fast the table is back (measured in during(), limit 2.5 s). Without the guard
# the table never comes back and the check below fails.
ALLOW=(comm:labtun comm:labtun-dig comm:labfree comm:labfree-dig comm:NetworkManager comm:systemd-resolve dns)
NOTE="Ein anderes Programm (Docker, fremdes VPN, Nutzer) leert alle nft-Regeln. Erwartung: Der Regeln-Waechter (1 s Takt) stellt sie wieder her; im Fenster davor ist Klartext unvermeidlich (ALLOW), geprueft wird die Zeit bis zur Rueckkehr (FAIL ab 2,5 s)."
during() {
	sleep 5
	client '
sudo -n nft flush ruleset; t0=$(date +%s%N)
n=0; until sudo -n nft list tables | grep "inet shunt" >/dev/null; do sleep 0.05; n=$((n+1)); [ $n -gt 200 ] && break; done
ms=$(( ($(date +%s%N) - t0) / 1000000 )); echo "Regeln zurueck nach $ms ms"
[ $ms -le 2500 ] || echo "FAIL Regeln erst nach $ms ms zurueck (Grenze 2500 ms)"'
	sleep 15
}
CLIENT='
for i in $(seq 30); do
  labtun -s -m2 -o /dev/null "http://$i-$1/" ; labfree -s -m2 -o /dev/null http://1.1.1.1/ ; labfree-dig +time=1 +tries=1 "d$i-$1" >/dev/null
  sleep 1
done
sudo -n nft list tables | grep -q "inet shunt" || echo "FAIL Tabelle inet shunt fehlt nach 30 s noch immer"
sudo -n systemctl restart shuntd; sleep 4
true
'
