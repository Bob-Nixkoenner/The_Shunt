ID=Q05
CONFIG=default
TITLE="Ruhemodus: LLMNR/mDNS/NetBIOS in der Registry aus, bei quiet=false die alten Werte zurueck"
EXPECT_CANARY=any
SETTLE=2
NOTE="Prueft per reg query: nach Dienststart EnableMulticast=0, EnableMDNS=0, NetbiosOptions=2 an jedem Tcpip_*; state\\quiet-registry.json vorhanden. Danach quiet=false (Konfig noquiet) wird in Q03 geprueft: Werte zurueck, Datei weg."
CLIENT='
$p="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
"EnableMulticast=" + (Get-ItemProperty $p -ErrorAction SilentlyContinue).EnableMulticast
"EnableMDNS=" + (Get-ItemProperty $p -ErrorAction SilentlyContinue).EnableMDNS
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | % { $_.PSChildName + " NetbiosOptions=" + (Get-ItemProperty $_.PSPath).NetbiosOptions }
"state file: " + (Test-Path "$env:ProgramData\Shunt\state\quiet-registry.json")
'
