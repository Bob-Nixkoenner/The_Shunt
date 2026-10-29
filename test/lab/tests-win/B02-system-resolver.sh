ID=B02
TITLE="Systemresolver (Dnscache) und Windows-Namensdienste verraten nichts"
EXPECT_CANARY=tunnel
NOTE="Windows fragt DNS parallel über alle Adapter (SMHNR), sendet LLMNR/mDNS und NetBIOS. Nichts davon darf im fremden Netz ankommen (DNS-Guard, Firewall-Regeln)."
CLIENT='
Clear-DnsClientCache
Resolve-DnsName $c -ErrorAction SilentlyContinue | Out-Null
Resolve-DnsName "w-$c" -LlmnrNetbiosOnly -ErrorAction SilentlyContinue | Out-Null
[System.Net.Dns]::GetHostEntry("x-$c") 2>$null | Out-Null
Start-Sleep 3
'
