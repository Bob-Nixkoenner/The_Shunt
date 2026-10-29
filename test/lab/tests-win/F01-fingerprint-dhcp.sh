ID=F01
TITLE="Tarnung: was verrät das Gerät beim Verbinden?"
RENEW=1
CHECKS=(fingerprint)
EXPECT_CANARY=any
NOTE="Neu verbinden, dann 20 s still mithören: DHCP-Optionen, MAC, IPv6-Adressen, LLMNR/mDNS/NetBIOS."
CLIENT='Start-Sleep 20; "Hostname: " + $env:COMPUTERNAME; Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias Ethernet | ForEach-Object { "v6: " + $_.IPAddress }'
