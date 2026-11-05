ID=C02
TITLE="IPv6 mit erreichbarem Ziel im Netz (globales Praefix): Tunnel hat kein v6, nichts geht direkt"
MODE=rogue-ra
EXPECT_CANARY=any
NOTE="Anders als E04 antwortet hier ein v6-Ziel: das Gateway bietet 2001:db8:77::/64 an und lauscht auf [2001:db8:77::1]:8080. Der Tunnel kann kein IPv6; das Ziel liegt im selben Netz (direkt erreichbar). Erwartung: weder die Tunnel-App noch die App ohne Regel erreicht es, am Gateway kommt kein IPv6-Paket vom Client an (Happy Eyeballs darf nicht auf v6 ausweichen)."
during() {
	sleep 3
	gw bash -c "timeout 60 python3 -m http.server 8080 --bind 2001:db8:77::1 >/dev/null 2>&1 &"
	sleep 2
	# control: the target really listens and answers on the gateway itself
	gw bash -c "ss -ltn | grep ':8080 '; curl -s -m3 -o /dev/null -w 'Kontrolle am Gateway: HTTP %{http_code}\\n' 'http://[2001:db8:77::1]:8080/'"
}
CLIENT='
sleep 8; ip -6 addr show scope global | grep inet6; ip -6 route | grep default
labtun -6 -s -m5 -o /dev/null http://[2001:db8:77::1]:8080/ && echo "FAIL Tunnel-App erreichte das v6-Ziel im fremden Netz"
labfree -6 -s -m5 -o /dev/null http://[2001:db8:77::1]:8080/ && echo "FAIL App ohne Regel erreichte das v6-Ziel im fremden Netz"
# Name mit nur v6-Adresse und v4-Adresse: muss ueber v4 durch den Tunnel gehen, nicht ueber v6
labtun -s -m8 -o /dev/null "http://$1/" || true
true
'
