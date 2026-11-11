ID=Q03
TITLE="Abwehr: dns_probe = off -> keine aktive DNS-Pruefung im fremden Netz"
CONFIG=defense-nodns
EXPECT_CANARY=any
# deliberately NO ALLOW for dns.google / one.one.one.one (see Q01): with dns_probe off the analyzer must
# not see those queries at the gateway or at the public resolver; if it does, it reports a leak
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
SETTLE=3
NOTE="Wie Q01, aber defense.dns_probe = off (configs/defense-nodns.toml). Die aktive DNS-Pruefung laeuft sonst 3 s nach
dem Netzbeitritt; der Client wartet hier 40 s (mehr als eine Runde) und der Analyzer darf KEINE Anfragen nach dns.google /
one.one.one.one am Gateway oder an 9.9.9.9 sehen (sonst Fund 'DNS ueber das fremde Netz'). Der passive Teil (Gateway-MAC-
Wechsel) bleibt an. Nicht in der Lab-VM gelaufen."
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 40
api /v1/defense | grep -o "\"dns_probe\":\"[a-z]*\""
api /v1/defense | grep -q "\"dns_probe\":\"off\"" || echo "FAIL dns_probe ist nicht off in der Konfiguration des Daemons"
true
'
