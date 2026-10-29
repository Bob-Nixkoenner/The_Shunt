ID=C01
TITLE="IPv6 (nur ULA im Netz): nichts geht per IPv6 am Tunnel vorbei"
CLIENT='
labtun -6 -s -m5 -o /dev/null http://[2606:4700:4700::1111]/ && echo "FAIL Tunnel-App erreichte IPv6-Ziel"
labfree -6 -s -m5 -o /dev/null http://[2606:4700:4700::1111]/ && echo "FAIL App ohne Regel erreichte IPv6-Ziel"
labtun -s -m8 -o /dev/null "http://$1/" || true
ip -6 addr show scope global | grep inet6
true
'
