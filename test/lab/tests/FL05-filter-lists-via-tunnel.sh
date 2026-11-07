ID=FL05
TITLE="DNS-Filter: Standardlisten werden über den Tunnel geladen"
CONFIG=filter-real
EXPECT_CANARY=none
SETTLE=3
PREP='sudo -n systemctl stop shuntd; sudo -n rm -rf /var/cache/shunt/blocklists; true'
NOTE="Cache leer, Standardlisten (hagezi usw.) werden beim Start geholt. Am Gateway darf kein Zugriff auf die Listen-Hosts erscheinen, nur der Tunnel-Transport; danach müssen Listen im Cache liegen."
CLIENT='
for i in $(seq 40); do n=$(sudo -n find /var/cache/shunt/blocklists -type f 2>/dev/null | wc -l); [ "$n" -ge 1 ] && break; sleep 3; done
echo "Listen im Cache: $n (nach $((i*3)) s)"
sudo -n ls -la /var/cache/shunt/blocklists 2>/dev/null | head -8
[ "$n" -ge 1 ] || echo "FAIL keine Listen geladen"
true
'
