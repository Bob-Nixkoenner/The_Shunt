ID=FL03
TITLE="DNS-Filter: Ausnahme (allow) wird aufgelöst, durch den Tunnel"
CONFIG=filter-lab-allow
EXPECT_CANARY=tunnel
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="shuntlab.test steht auf der Liste und auf allow. Die Anfrage muss durchgelassen werden und über den Tunnel laufen (CT130), nicht zum Gateway."
CLIENT='
st() { labtun-dig +time=2 +tries=1 "$1" "$2" | grep -o "status: [A-Z]*" | head -1; }
echo "A $(st "$1" A)"
true
'
