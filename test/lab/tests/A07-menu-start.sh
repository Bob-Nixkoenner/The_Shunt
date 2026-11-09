ID=A07
TITLE="Start aus dem Menü: Tunnel-App (Regel) bei Standardweg direkt"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp net:0.0.0.0/0:123/udp net:::/0:123/udp net:185.199.108.0/22:443/tcp comm:NetworkManager comm:apt comm:isahc-agent comm:systemd-timesyn comm:systemd-timesyncd comm:http net:2606:50c0::/32:443/tcp host:.pop-os.org:80/tcp host:api.pop-os.org:443/tcp host:.fedoraproject.org:80/tcp) # default route direct: the distro's connectivity check and NTP may go direct
NOTE="Wie A06, aber über einen Menüeintrag (gio launch). Bei Standardweg direkt ist Hintergrundverkehr der Distribution (apt, NetworkManager, Blocklisten-Download) gewollt direkt; die App selbst darf nichts direkt senden."
CLIENT='
f=/usr/share/applications/labtun-menu.desktop
printf "[Desktop Entry]\nType=Application\nName=Lab Tunnel App\nExec=labtun -s -m8 -o /dev/null http://$1/\nCategories=Network;\n" | sudo -n tee $f >/dev/null; sudo -n chmod 644 $f
rm -f ~/.local/share/applications/labtun-menu.desktop
gio launch $f; sleep 10
'
