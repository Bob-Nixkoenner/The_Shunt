ID=A04
TITLE="Systemdienst (root, systemd-run) nimmt den Standardweg"
CLIENT='
sudo -n systemd-run --wait --pipe -q curl -s -m8 -o /dev/null "http://$1/" || true
ip=$(sudo -n systemd-run --wait --pipe -q curl -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ $ip == 198.51.100.230 ]] || echo "FAIL Ausgangs-IP $ip statt CT130"
'
