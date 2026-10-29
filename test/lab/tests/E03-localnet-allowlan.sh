ID=E03
TITLE="TunnelCrack LocalNet mit allow_lan = true"
MODE=localnet
CONFIG=allowlan
NOTE="allow_lan soll nur private, direkt angeschlossene Netze freigeben; 1.1.1.0/24 ist öffentlich."
CLIENT='
labtun -s -m8 -o /dev/null "http://$1/" || true
labtun -s -m8 -o /dev/null http://1.1.1.1/ || true
labtun-dig +time=3 @1.1.1.1 "d-$1" >/dev/null || true
'
