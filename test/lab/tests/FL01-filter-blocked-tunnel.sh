ID=FL01
TITLE="DNS-Filter: gesperrter Name verlässt das Gerät nicht (App im Tunnel)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="Lokale Liste sperrt *.shuntlab.test. Der Canary darf weder am Gateway noch am Tunnel-Ausgang auftauchen; der Client bekommt NXDOMAIN (A und AAAA)."
CLIENT='
st() { labtun-dig +time=2 +tries=1 "$1" "$2" | grep -o "status: [A-Z]*" | head -1; }
a=$(st "$1" A); q=$(st "$1" AAAA)
echo "A $a, AAAA $q"
case "$a" in *NXDOMAIN*) ;; *) echo "FAIL A-Anfrage nicht gesperrt ($a)";; esac
case "$q" in *NXDOMAIN*) ;; *) echo "FAIL AAAA-Anfrage nicht gesperrt ($q)";; esac
true
'
