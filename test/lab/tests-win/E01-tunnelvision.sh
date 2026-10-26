ID=E01
TITLE="TunnelVision: DHCP Option 121 lenkt Routen am Tunnel vorbei"
MODE=tunnelvision
NOTE="CVE-2024-3661. Das Gateway verteilt 0.0.0.0/1 und 128.0.0.0/1 über sich selbst."
CLIENT='
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in "0.0.0.0/0","0.0.0.0/1","128.0.0.0/1" } | ForEach-Object { "Route " + $_.DestinationPrefix + " via " + $_.NextHop + " (" + $_.InterfaceAlias + ")" }
& C:\lab\labtun.exe -s -m8 -o NUL "http://$c/"
& C:\lab\labfree.exe -s -m8 -o NUL "http://f-$c/"
$ip = & C:\lab\labtun.exe -s -m8 http://ifconfig.me/ip; "Tunnel-App: $ip"
if ($ip -ne "185.216.213.230") { "FAIL Tunnel-App kam als $ip raus" }
'
