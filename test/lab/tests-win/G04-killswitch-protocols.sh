ID=G04
TITLE="Tunnel weg: auch NTP, QUIC, Ping, DNS bleiben gesperrt"
MODE=tunnelkill
EXPECT_CANARY=none
CLIENT='
Start-Sleep 3
foreach ($t in @("162.159.200.1",123),@("1.1.1.1",443)) { try { $u = New-Object Net.Sockets.UdpClient; [void]$u.Send([byte[]](120),1,$t[0],$t[1]); $u.Close() } catch {} }
Resolve-DnsName $c -Server 9.9.9.9 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
if (Test-Connection 1.1.1.1 -Count 2 -Quiet) { "FAIL Ping ging raus, obwohl der Tunnel weg ist" }
w32tm /stripchart /computer:162.159.200.1 /samples:1 /dataonly 2>&1 | Select-Object -Last 1
'
