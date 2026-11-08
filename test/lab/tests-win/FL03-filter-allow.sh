ID=FL03
TITLE="DNS-Filter: Ausnahme (allow) wird aufgelöst, durch den Tunnel"
CONFIG=filter-lab-allow
EXPECT_CANARY=tunnel
PREP='Set-Content -Encoding ascii C:\ProgramData\Shunt\lab-filter.txt "||shuntlab.test^"'
NOTE="shuntlab.test steht auf der Liste und auf allow. Die Anfrage an 10.111.0.53 muss durchgelassen werden und ueber den Tunnel laufen (CT130), nicht zum Gateway."
CLIENT='
function Nx($n,$t) { $r = Resolve-DnsName $n -Type $t -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue -ErrorVariable e; if ($r) { "Antwort" } elseif ($e -and $e[0].Exception.NativeErrorCode -eq 9003) { "NXDOMAIN" } else { "anders: " + $e[0].Exception.Message } }
$a = Nx $c A; "A $a"
if ($a -eq "NXDOMAIN") { "FAIL Ausnahme greift nicht: NXDOMAIN" }
'
