ID=E04
TITLE="Falsche IPv6-Router-Werbung (globales Präfix + DNS)"
MODE=rogue-ra
NOTE="Das Gateway kündigt 2001:db8:77::/64 mit hoher Priorität an. Ein Gerät mit IPv6 versucht dann IPv6 am Tunnel vorbei."
CLIENT='
sleep 5; ip -6 addr show scope global | grep inet6; ip -6 route | grep default
labtun -s -m5 -o /dev/null "http://$1/" || true
labtun -6 -s -m5 -o /dev/null http://[2606:4700:4700::1111]/ && echo "FAIL Tunnel-App sprach IPv6 direkt"
labfree -s -m5 -o /dev/null http://ipv6.google.com/ && echo "FAIL App ohne Regel sprach IPv6 direkt"
resolvectl dns 2>/dev/null | head -3
true
'
