ID=FL06
TITLE="DNS-Filter: Listen-Download bei default_route = direct (Dokumentation)"
CONFIG=filter-real-direct
EXPECT_CANARY=any
ALLOW=(comm:shuntd dns net:185.199.108.0/22:443/tcp comm:systemd-timesyn comm:chronyd comm:ntpd)
SETTLE=3
PREP='sudo -n systemctl stop shuntd; sudo -n rm -rf /var/cache/shunt/blocklists; true'
NOTE="Gewollt (#8): Der Listen-Download folgt der Standardroute. Ist sie direct, gehen DNS und HTTPS der Listen-Hosts ins fremde Netz. Das gilt für jeden Systemdienst ohne Regel, auch den Zeitabgleich (NTP, UDP/123: systemd-timesyncd, chrony): direkt ist hier der Standardweg, kein Leck. Dieser Test hält das als Doku fest; Ergebnis im Bericht prüfen, nicht als Fehler werten."
CLIENT='
for i in $(seq 40); do n=$(sudo -n find /var/cache/shunt/blocklists -type f 2>/dev/null | wc -l); [ "$n" -ge 1 ] && break; sleep 3; done
echo "Listen im Cache: $n (nach $((i*3)) s)"
true
'
