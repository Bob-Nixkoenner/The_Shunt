ID=G01
TITLE="Portscan aus dem fremden Netz"
SCAN=1
EXPECT_CANARY=any
NOTE="nmap vom Gateway: TCP alle Ports, UDP Top 200, IPv4 + IPv6 link-local. 7680/tcp ist die Windows-
Uebermittlungsoptimierung (DoSvc, geschuetzter Dienst, in der Lab-VM nicht abschaltbar): erlaubt, kein Fund
des Shunt (Bericht windows-h10-laptop-2026-11-13, Fund 4)."
# Delivery Optimization listens on 7680 by itself; the Shunt's inbound protection is tested in Q/G02
EXPECT_OPEN=("7680/tcp")
CLIENT='
Start-Sleep 5
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin "127.0.0.1","::1" } | ForEach-Object { "lauscht: tcp " + $_.LocalAddress + ":" + $_.LocalPort + " " + (Get-Process -Id $_.OwningProcess).ProcessName }
Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin "127.0.0.1","::1" } | ForEach-Object { "lauscht: udp " + $_.LocalAddress + ":" + $_.LocalPort + " " + (Get-Process -Id $_.OwningProcess).ProcessName } | Sort-Object -Unique
'
