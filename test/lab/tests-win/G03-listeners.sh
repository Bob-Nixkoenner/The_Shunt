ID=G03
TITLE="Lauschende Dienste: Shunt-API/UI nur lokal?"
EXPECT_CANARY=any
CLIENT='
Get-NetTCPConnection -State Listen | ForEach-Object { "tcp: " + $_.LocalAddress + ":" + $_.LocalPort + " " + (Get-Process -Id $_.OwningProcess).ProcessName } | Sort-Object -Unique
Get-NetTCPConnection -State Listen | Where-Object { (Get-Process -Id $_.OwningProcess).ProcessName -like "shunt*" -and $_.LocalAddress -notin "127.0.0.1","::1" } | ForEach-Object { "FAIL shunt lauscht nicht nur lokal: " + $_.LocalAddress + ":" + $_.LocalPort }
'
