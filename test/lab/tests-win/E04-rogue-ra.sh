ID=E04
TITLE="Falsche IPv6-Router-Werbung (globales Präfix + DNS)"
MODE=rogue-ra
NOTE="Das Gateway kündigt 2001:db8:77::/64 mit hoher Priorität an. Ein Gerät mit IPv6 versucht dann IPv6 am Tunnel vorbei."
CLIENT='
Start-Sleep 5
Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias Ethernet | ForEach-Object { "v6: " + $_.IPAddress }
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix ::/0 -ErrorAction SilentlyContinue | ForEach-Object { "v6-Default via " + $_.NextHop + " (" + $_.InterfaceAlias + ")" }
& C:\lab\labtun.exe -s -m5 -o NUL "http://$c/"
& C:\lab\labtun.exe -6 -s -m5 -o NUL "http://[2606:4700:4700::1111]/"; if ($LASTEXITCODE -eq 0) { "FAIL Tunnel-App sprach IPv6 direkt" }
& C:\lab\labfree.exe -s -m5 -o NUL http://ipv6.google.com/; if ($LASTEXITCODE -eq 0) { "FAIL App ohne Regel sprach IPv6 direkt" }
(Get-DnsClientServerAddress -InterfaceAlias Ethernet -AddressFamily IPv6).ServerAddresses | ForEach-Object { "v6-DNS: $_" }
'
