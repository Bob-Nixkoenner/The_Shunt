ID=FL02
TITLE="DNS-Filter: gesperrter Name verlässt das Gerät nicht (App direkt)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="Wie FL01, aber die App hat die Route direct. Wichtig: Die Anfrage darf nicht beim Café-DNS (Gateway) landen."
CLIENT='
st() { labdir-dig +time=2 +tries=1 "$1" "$2" | grep -o "status: [A-Z]*" | head -1; }
a=$(st "$1" A); q=$(st "$1" AAAA)
echo "A $a, AAAA $q"
case "$a" in *NXDOMAIN*) ;; *) echo "FAIL A-Anfrage nicht gesperrt ($a)";; esac
case "$q" in *NXDOMAIN*) ;; *) echo "FAIL AAAA-Anfrage nicht gesperrt ($q)";; esac
true
'
