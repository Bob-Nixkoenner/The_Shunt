ID=E03
TITLE="TunnelCrack LocalNet mit allow_lan = true"
MODE=localnet
CONFIG=allowlan
NOTE="allow_lan soll nur private, direkt angeschlossene Netze freigeben; 1.1.1.0/24 ist öffentlich."
CLIENT='
& C:\lab\labtun.exe -s -m8 -o NUL "http://$c/"
& C:\lab\labtun.exe -s -m8 -o NUL http://1.1.1.1/
Resolve-DnsName "d-$c" -Server 1.1.1.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
'
