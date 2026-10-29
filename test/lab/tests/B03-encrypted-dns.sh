ID=B03
TITLE="DoT/DoH: Port 853 gesperrt, bekannte DoH-Namen ohne Antwort"
EXPECT_CANARY=none
CLIENT='
if labtun-nc -z -w3 1.1.1.1 853; then echo "FAIL DoT (853) zu 1.1.1.1 ist offen"; else echo "853 zu"; fi
a=$(labtun-dig +short +time=3 dns.google A | head -1); echo "dns.google → ${a:-NXDOMAIN/leer}"
a=$(labtun-dig +short +time=3 cloudflare-dns.com A | head -1); echo "cloudflare-dns.com → ${a:-NXDOMAIN/leer}"
'
