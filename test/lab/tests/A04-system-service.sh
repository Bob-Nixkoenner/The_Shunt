ID=A04
TITLE="Systemdienst (root, systemd-run) nimmt den Standardweg"
CLIENT='
# no --pipe: on Fedora 45 (systemd 262) it fails over guest control ("Connection reset by peer" / "Bad message"); capture via a file instead
sysrun() { sudo -n systemd-run --wait --collect -q "$@"; }
sysrun curl -s -m8 -o /dev/null "http://$1/" || true
sudo -n rm -f /tmp/a04.out
sysrun -p StandardOutput=file:/tmp/a04.out curl -s -m8 http://ifconfig.me/ip || true
ip=$(sudo -n cat /tmp/a04.out 2>/dev/null); echo "Ausgangs-IP: $ip"
[[ $ip == 185.216.213.230 ]] || echo "FAIL Ausgangs-IP $ip statt CT130"
'
