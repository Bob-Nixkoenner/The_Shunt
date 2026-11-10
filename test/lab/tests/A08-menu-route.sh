ID=A08
TITLE="Start aus dem Menü in der Route der Regel (shunt desktop set)"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd comm:NetworkManager comm:systemd-timesyn comm:systemd-timesyncd comm:pacman comm:apt comm:isahc-agent net:185.199.108.0/22:443/tcp dns net:0.0.0.0/0:123/udp net:::/0:123/udp net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp comm:http net:2606:50c0::/32:443/tcp host:.pop-os.org:80/tcp host:api.pop-os.org:443/tcp host:.fedoraproject.org:80/tcp net:2620:52:6::/48:80/tcp net:2600:1f18:568d::/48:80/tcp net:2606:f640:6000::/48:80/tcp net:2600:1f14:fad::/48:80/tcp net:2604:1580:fe00::/48:80/tcp net:2605:bc80:3010::/48:80/tcp) # default route direct: background traffic of the distro (connectivity check, NTP even when the trace misses the process, updates on Arch) may go direct
NOTE="Menüeintrag wie A07, vorher auf die Route der Regel gesetzt (wie der Link in der Regelliste): startet über shunt run, nichts darf direkt rausgehen."
CLIENT='
f=/usr/share/applications/labtun-menu.desktop
printf "[Desktop Entry]\nType=Application\nName=Lab Tunnel App\nExec=labtun -s -m8 -o /dev/null http://$1/\nCategories=Network;\n" | sudo -n tee $f >/dev/null; sudo -n chmod 644 $f
shunt desktop set labtun-menu tunnel:intern || echo "FAIL shunt desktop set"
grep ^Exec ~/.local/share/applications/labtun-menu.desktop
gio launch ~/.local/share/applications/labtun-menu.desktop; sleep 10
'
