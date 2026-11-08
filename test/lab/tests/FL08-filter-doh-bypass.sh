ID=FL08
TITLE="DNS-Filter: Umgehung über DoH zu einer IP (curl --doh-url)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='printf "%s\n" "||shuntlab.test^" | sudo -n tee /etc/shunt/lab-filter.txt >/dev/null'
NOTE="Ein Programm, das DoH selbst spricht (hier curl zu 1.1.1.1), sieht den Filter nicht. Geht die Anfrage durch, taucht der Canary am Tunnel-Ausgang auf: das ist dann ein dokumentierter Fund (der Filter sieht DoH-Apps nicht), kein Fehler im Test."
CLIENT='
labtun -s -m6 --doh-url https://1.1.1.1/dns-query -o /dev/null "http://$1/"; echo "curl-Ende: $?"
true
'
