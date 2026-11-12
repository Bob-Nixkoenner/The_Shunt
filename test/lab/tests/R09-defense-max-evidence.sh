ID=R09
TITLE="Abwehr: Max. Sicherheit mit Beweissicherung laeuft unter der echten Unit (kein SIGSYS, Zurueckschalten geht)"
CONFIG=defense-max
EXPECT_CANARY=any
ALLOW=(dnsname:dns.google dnsname:one.one.one.one)
EXPECT_OPEN=("23/tcp" "80/tcp" "445/tcp" "3389/tcp")
NOTE="Gegenprobe zum Fund 12.11. (adjtimex, status=31/SYS, 119 Neustarts): Evidenz an + Mitschnitt wie bei Max. Sicherheit. Erwartet: shuntd aktiv, NRestarts 0, kein Seccomp-Abschuss, state_clock mit bekanntem Zustand, danach Evidenz aus per Konfig + reload ohne Absturz. Nicht in der Lab-VM gelaufen (Stand 12.11.)."
CLIENT='
api() { curl -s --unix-socket /run/shunt/shuntd.sock "http://shunt$1"; }
sleep 8
systemctl is-active -q shuntd || echo "FAIL shuntd nicht aktiv"
n=$(systemctl show -p NRestarts --value shuntd); echo "NRestarts=$n"; [ "$n" = 0 ] || echo "FAIL shuntd neu gestartet ($n)"
sudo -n journalctl -u shuntd -b --no-pager | grep -q "status=31/SYS" && echo "FAIL shuntd per Seccomp abgeschossen"
sudo -n journalctl -k -b --no-pager | grep "comm=\"shuntd\"" | grep -q "type=1326\|SECCOMP" && echo "INFO Seccomp-Meldung zu shuntd: $(sudo -n journalctl -k -b --no-pager | grep -m1 "comm=\"shuntd\"")"
api /v1/defense/evidence | grep -q "\"enabled\":true" || echo "FAIL Evidenz meldet nicht enabled"
clk=$(sudo -n sh -c "grep -rh state_clock /var/lib/shunt/evidence 2>/dev/null" | tail -1)
echo "state_clock: $clk"
case $clk in *ntp_synchronized=yes*|*ntp_synchronized=no*) ;; *) echo "FAIL state_clock fehlt oder Uhrstatus unbekannt";; esac
# switch back: evidence off by config + reload, shuntd must stay up
sudo -n sed -i "/^\\[defense.evidence\\]/,/^\\[/ s/^enabled = true\$/enabled = false/" /etc/shunt/shunt.toml
sudo -n systemctl reload shuntd; sleep 4
systemctl is-active -q shuntd && api /v1/defense/evidence | grep -q "\"enabled\":false" || echo "FAIL Zurueckschalten (Evidenz aus) klappt nicht"
true
'
