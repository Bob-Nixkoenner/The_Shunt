ID=A07
TITLE="Start aus dem Menü: Tunnel-App (Regel) bei Standardweg direkt"
CONFIG=direct
ALLOW=(comm:labdir comm:labfree comm:curl comm:chronyd dns net:2620:2d:4000::/46:80/tcp net:185.125.188.0/22:80/tcp net:91.189.88.0/21:80/tcp) # default route direct: Ubuntu's connectivity check may go direct
NOTE="Wie A06, aber über einen Menüeintrag (gio launch). Erwartet: Fund wie A06 (Start-Wettlauf, Fix-Plan #6)."
CLIENT='
f=/usr/share/applications/labtun-menu.desktop
printf "[Desktop Entry]\nType=Application\nName=Lab Tunnel App\nExec=labtun -s -m8 -o /dev/null http://$1/\nCategories=Network;\n" | sudo -n tee $f >/dev/null; sudo -n chmod 644 $f
rm -f ~/.local/share/applications/labtun-menu.desktop
gio launch $f; sleep 10
'
