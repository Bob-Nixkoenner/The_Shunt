ID=FL07
TITLE="DNS-Filter: Tunnel fällt aus, gesperrte Namen bleiben lokal gesperrt"
CONFIG=filter-lab
EXPECT_CANARY=none
ALLOW=(dst:151.101.1.91:80/tcp)
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="Nach 6 s schaltet das Gateway den Tunnel-Server weg (tunnelkill). Gesperrte Namen müssen weiter lokal mit NXDOMAIN beantwortet werden und dürfen nirgends auftauchen. Erlaubt: Portal-Prüfung von shuntd wie bei D01."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
bad=0
for i in $(seq 12); do
  s=$(labtun-dig +time=1 +tries=1 "d$i-$1" A | grep -o "status: [A-Z]*" | head -1)
  case "$s" in *NXDOMAIN*) ;; *) bad=$((bad+1)); echo "Anfrage $i: $s";; esac
  sleep 1
done
echo "nicht gesperrt beantwortet: $bad von 12"
[ "$bad" -eq 0 ] || echo "FAIL $bad Anfragen ohne NXDOMAIN nach Tunnelausfall"
true
'
