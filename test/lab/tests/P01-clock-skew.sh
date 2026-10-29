ID=P01
TITLE="Uhr 10 Minuten falsch: shunt status warnt (Uhr ueber den Tunnel geprueft)"
EXPECT_CANARY=any
SETTLE=1
NOTE="Systemuhr +10 min, shuntd neu starten, nach 40 s muss der Status warnen. Pruefung laeuft ueber den Tunnel (HTTPS Date-Header), nie im Klartext im fremden Netz (Analyzer)."
CLIENT='
sudo -n systemctl stop chrony chronyd systemd-timesyncd 2>/dev/null
sudo -n timedatectl set-ntp false 2>/dev/null
sudo -n date -s "+10 minutes" >/dev/null
sudo -n systemctl restart shuntd; sleep 45
sudo -n shunt status 2>&1 | grep -i "clock" || echo "FAIL Status warnt nicht vor der falschen Uhr"
sudo -n date -s "-10 minutes" >/dev/null
sudo -n timedatectl set-ntp true 2>/dev/null; sudo -n systemctl start chrony 2>/dev/null
sudo -n systemctl restart shuntd; sleep 45
sudo -n shunt status 2>&1 | grep -i "system clock" && echo "FAIL Warnung bleibt trotz richtiger Uhr"
true
'
