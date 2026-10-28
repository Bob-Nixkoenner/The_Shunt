ID=P04
TITLE="tcp_timestamps = off: direkte Verbindung zeigt keine TCP-Zeitstempel"
CONFIG=tcpts-off
EXPECT_CANARY=any
ALLOW=(comm:labdir)
NOTE="labdir (direkt) verbindet zum Lab-Gateway; das Gateway schneidet das SYN mit und sucht die TS-Option. Danach ist der Systemwert wieder da (restart)."
during() {
	sleep 3
	read -r _ cip _ <<<"$(gw labctl client)"
	gw timeout 12 tcpdump -nn -v -c 3 -i enp0s8 "tcp[tcpflags] == tcp-syn and dst port 80 and src host $cip" >/tmp/p04.$$ 2>&1
	grep -q "TS val" /tmp/p04.$$ && echo "FAIL SYN mit TCP-Zeitstempel (TS val)"
	grep -c "flags \[S\]" /tmp/p04.$$ | grep -q '^0$' && echo "FAIL kein SYN mitgeschnitten"
	cat /tmp/p04.$$; rm -f /tmp/p04.$$
}
CLIENT='
[ "$(cat /proc/sys/net/ipv4/tcp_timestamps)" = 0 ] || echo "FAIL sysctl tcp_timestamps ist nicht 0"
for i in 1 2 3; do labdir -s -m3 -o /dev/null http://10.77.0.1/; sleep 1; done
true
'
