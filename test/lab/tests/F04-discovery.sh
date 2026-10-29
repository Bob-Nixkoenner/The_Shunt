ID=F04
TITLE="Tarnung: Discovery-Rundrufe (KDE Connect, Syncthing, mDNS, LLMNR) im fremden Netz"
CHECKS=(fingerprint)
EXPECT_CANARY=any
NOTE="Typische Rundrufe von Apps, die andere Geräte suchen. Im fremden Netz verraten sie Gerätename und IDs (Syncthing-ID ist weltweit eindeutig). Getunnelte Apps lehnt Shunt ab; Apps auf „direkt“ rufen heute ins fremde Netz (Ruhemodus fehlt, tarnung-fremde-netze.md T1): erwartet Fund."
CLIENT='
cat >/tmp/f04.py <<PY
import socket, json, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
kde = json.dumps({"id": 0, "type": "kdeconnect.identity", "body": {"deviceId": "lab_device_0123456789", "deviceName": "lab-laptop", "deviceType": "laptop", "protocolVersion": 7, "tcpPort": 1716}}).encode() + b"\\n"
sync = json.dumps({"deviceId": "LABSYNC-0123456-ABCDEFG-HIJKLMN", "addresses": ["tcp://0.0.0.0:22000"]}).encode()
for _ in range(3):
    for data, port in ((kde, 1716), (sync, 21027)):
        try:
            s.sendto(data, ("255.255.255.255", port))
        except OSError as e:  # Shunt rejects broadcasts of tunnelled apps
            print(sys.argv[1], port, "abgelehnt:", e.strerror)
    time.sleep(1)
PY
# an app on the default route (tunnel) and one that goes direct (e.g. KDE Connect for the LAN)
python3 /tmp/f04.py tunnel
sudo -n shunt run --via direct -- python3 /tmp/f04.py direkt
rm -f /tmp/f04.py
resolvectl query lab-nachbar 2>/dev/null | head -1 || true
avahi-resolve -n lab-nachbar.local 2>/dev/null || true
sleep 3
'
