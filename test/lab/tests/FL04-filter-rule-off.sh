ID=FL04
TITLE="DNS-Filter: Regel dns_filter = off gilt nur für ihre Apps"
CONFIG=filter-lab-off
EXPECT_CANARY=tunnel
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="Die Tunnel-Lab-Apps haben dns_filter = off, die direkte Lab-App nicht. labtun-dig kommt durch (Tunnel), labdir-dig bleibt gesperrt. Landet die direkte Anfrage am Gateway, ist das ein Fund."
CLIENT='
st() { $1 +time=2 +tries=1 "$2" A | grep -o "status: [A-Z]*" | head -1; }
d=$(st labdir-dig "$1")
echo "labdir-dig (Filter an): $d"
case "$d" in *NXDOMAIN*) ;; *) echo "FAIL direkte App nicht gesperrt ($d)";; esac
echo "labtun-dig (Filter aus): $(st labtun-dig "$1")"
true
'
