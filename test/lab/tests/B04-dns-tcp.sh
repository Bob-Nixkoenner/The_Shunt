ID=B04
TITLE="DNS über TCP und große Antworten bleiben im Tunnel"
CLIENT='
labtun-dig +tcp +time=3 "$1" A || true
labtun-dig +time=3 +bufsize=4096 TXT google.com >/dev/null || true
labtun-dig +time=3 +dnssec DNSKEY org >/dev/null || true
'
