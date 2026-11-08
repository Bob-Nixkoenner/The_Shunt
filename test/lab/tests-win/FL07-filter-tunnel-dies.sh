ID=FL07
TITLE="DNS-Filter: Tunnel fällt aus, gesperrte Namen bleiben lokal gesperrt"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='Set-Content -Encoding ascii C:\ProgramData\Shunt\lab-filter.txt "||shuntlab.test^"'
NOTE="Nach 6 s schaltet das Gateway den Tunnel-Server weg (tunnelkill). Gesperrte Namen muessen weiter lokal mit NXDOMAIN beantwortet werden und duerfen nirgends auftauchen."
during() { sleep 6; gw labctl mode tunnelkill; }
CLIENT='
function Nx($n,$t) { $r = Resolve-DnsName $n -Type $t -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue -ErrorVariable e; if ($r) { "Antwort" } elseif ($e -and $e[0].Exception.NativeErrorCode -eq 9003) { "NXDOMAIN" } else { "anders: " + $e[0].Exception.Message } }
$bad=0
1..12 | ForEach-Object { $s = Nx "d$_-$c" A; if ($s -ne "NXDOMAIN") { $bad++; "Anfrage ${_}: $s" }; Start-Sleep 1 }
"nicht gesperrt beantwortet: $bad von 12"
if ($bad -gt 0) { "FAIL $bad Anfragen ohne NXDOMAIN nach Tunnelausfall" }
'
