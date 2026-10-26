ID=G01
TITLE="Portscan aus dem fremden Netz"
SCAN=1
EXPECT_CANARY=any
NOTE="nmap vom Gateway: TCP alle Ports, UDP Top 200, IPv4 + IPv6 link-local."
CLIENT='
Start-Sleep 5
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin "127.0.0.1","::1" } | ForEach-Object { "lauscht: tcp " + $_.LocalAddress + ":" + $_.LocalPort + " " + (Get-Process -Id $_.OwningProcess).ProcessName }
Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin "127.0.0.1","::1" } | ForEach-Object { "lauscht: udp " + $_.LocalAddress + ":" + $_.LocalPort + " " + (Get-Process -Id $_.OwningProcess).ProcessName } | Sort-Object -Unique
'
