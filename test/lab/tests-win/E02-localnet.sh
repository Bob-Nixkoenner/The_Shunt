ID=E02
TITLE="TunnelCrack LocalNet: das Netz gibt sich als 1.1.1.0/24 aus"
MODE=localnet
NOTE="Der Tunnel-DNS 1.1.1.1 liegt jetzt scheinbar im lokalen Netz. Er darf trotzdem nur durch den Tunnel gefragt werden."
CLIENT='
Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet | ForEach-Object { "v4: " + $_.IPAddress }
& C:\lab\labtun.exe -s -m8 -o NUL "http://$c/"
& C:\lab\labtun.exe -s -m8 -o NUL http://1.1.1.1/
$ip = & C:\lab\labtun.exe -s -m8 http://ifconfig.me/ip; "Tunnel-App: $ip"
if ($ip -ne "185.216.213.230") { "FAIL Tunnel-App kam als $ip raus" }
'
