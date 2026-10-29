ID=C01
TITLE="IPv6 (nur ULA im Netz): nichts geht per IPv6 am Tunnel vorbei"
CLIENT='
& C:\lab\labtun.exe -6 -s -m5 -o NUL "http://[2606:4700:4700::1111]/"; if ($LASTEXITCODE -eq 0) { "FAIL Tunnel-App erreichte IPv6-Ziel" }
& C:\lab\labfree.exe -6 -s -m5 -o NUL "http://[2606:4700:4700::1111]/"; if ($LASTEXITCODE -eq 0) { "FAIL App ohne Regel erreichte IPv6-Ziel" }
& C:\lab\labtun.exe -s -m8 -o NUL "http://$c/"
Get-NetIPAddress -AddressFamily IPv6 | Where-Object PrefixOrigin -ne WellKnown | ForEach-Object { "v6: " + $_.IPAddress + " (" + $_.InterfaceAlias + ")" }
'
