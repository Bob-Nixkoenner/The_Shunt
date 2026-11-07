ID=MH05
TITLE="Multi-Hop WireGuard in OpenVPN: das fremde Netz sieht nur OpenVPN"
CONFIG=hop-wg-in-ovpn
NOTE="Aeusserer Hop OpenVPN (UDP 1194), innerer Hop WireGuard (10.67.0.1:51830 durch OpenVPN). Gateway sieht nur 1194/udp, nie 51830. Mitschnitt CT130_IF=wgt0."
CLIENT='
sleep 10
for i in $(seq 5); do labtun -s -m4 -o /dev/null "http://$i-$1/"; labtun-dig +time=2 +tries=1 "d$i-$1" >/dev/null; sleep 1; done
ip=$(labtun -s -m8 http://ifconfig.me/ip); echo "Ausgangs-IP: $ip"
[[ -n $ip ]] || echo "FAIL Tunnel-App ueber WireGuard-in-OpenVPN ohne Antwort"
true
'
