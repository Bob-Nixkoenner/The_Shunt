ID=Q02
CONFIG=trusted
TITLE="Vertrautes Netz (inbound=lan): Ruhemodus aus, die Rundrufe kommen raus (Gegenprobe zu Q01)"
EXPECT_CANARY=any
SETTLE=2
QUIET_STOP=${QUIET_STOP:-0}
NOTE="Der Test schickt selbst UDP an 137/138/5355/5353/1900 (Broadcast, Multicast v4/v6, gebunden und ungebunden) plus LLMNR-/NetBIOS-Abfragen von Windows. QUIET_STOP=1: Dienst vorher gestoppt (Filter muessen trotzdem halten). Auswertung am Gateway: Pakete mit Nutzlast QPROBE im Mitschnitt (Q01/Q04: keine erwartet; Q02/Q03 Gegenprobe: alle sichtbar)."
CLIENT='
$stop='$QUIET_STOP'
if ($stop -eq 1) { Stop-Service Shunt -WarningAction SilentlyContinue; Start-Sleep 3 }
$ifx=(Get-NetAdapter Ethernet).ifIndex
function Snd($ip,$port,$bind) {
  $v6 = $ip -like "ff*"
  if ($v6) { $u=New-Object Net.Sockets.UdpClient ([Net.Sockets.AddressFamily]::InterNetworkV6); $addr=[Net.IPAddress]::Parse($ip); $addr.ScopeId=$ifx }
  else { $u=New-Object Net.Sockets.UdpClient; $addr=[Net.IPAddress]::Parse($ip); $u.Client.SetSocketOption("Socket","Broadcast",$true) }
  if ($bind) { $any = if ($v6) { [Net.IPAddress]::IPv6Any } else { [Net.IPAddress]::Any }; $u.Client.Bind((New-Object Net.IPEndPoint ($any,(50000+$port%1000)))) }
  $b=[Text.Encoding]::ASCII.GetBytes("QPROBE-$c")
  $ep=New-Object Net.IPEndPoint ($addr,$port)
  try { $n=$u.Send($b,$b.Length,$ep); "send $ip`:$port bind=$bind ok" } catch { "send $ip`:$port bind=$bind ERR " + $_.Exception.Message }
  $u.Close()
}
foreach ($bind in $false,$true) {
 foreach ($t in "255.255.255.255:137","10.77.0.255:137","255.255.255.255:138","224.0.0.252:5355","224.0.0.251:5353","239.255.255.250:1900","255.255.255.255:21027","224.0.0.251:1716","ff02::1:3:5355","ff02::fb:5353","ff02::c:1900") {
   $i=$t.LastIndexOf(":"); Snd $t.Substring(0,$i) ([int]$t.Substring($i+1)) $bind } }
"-- Windows-eigene Abfragen"
Resolve-DnsName "qllmnr-$c" -LlmnrOnly -NoHostsFile -ErrorAction SilentlyContinue | Out-Null
Resolve-DnsName "qmdns-$c.local" -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Out-Null
nbtstat -a "QNB-$c" 2>&1 | Select -First 3
ping -n 1 -w 1000 "qping-$c" 2>&1 | Select -First 2
Start-Sleep 5
if ($stop -eq 1) { Start-Service Shunt; Start-Sleep 5 }
'
