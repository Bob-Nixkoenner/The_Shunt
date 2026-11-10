ID=FL02
TITLE="DNS-Filter: gesperrter Name verlässt das Gerät nicht (App direkt)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='Set-Content -Encoding ascii C:\ProgramData\Shunt\lab-filter.txt "||shuntlab.test^"'
NOTE="Wie FL01, aber mit labdir (Route direct). Wichtig: Die Anfrage darf nicht beim Café-DNS (Gateway) landen. Unter Windows fragt Dnscache fuer die App, nicht die App selbst: der Test zeigt, dass auch der Name einer direkten App nicht ins fremde Netz geht."
CLIENT='
function Nx($n,$t) { $r = Resolve-DnsName $n -Type $t -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue -ErrorVariable e; if ($r) { "Antwort" } elseif ($e -and $e[0].Exception.NativeErrorCode -eq 9003) { "NXDOMAIN" } else { "anders: " + $e[0].Exception.Message } }
& C:\lab\labdir.exe -s -m6 -o NUL "http://$c/"; $x=$LASTEXITCODE; "labdir curl-Ende: $x"
# 28 = timeout: after NXDOMAIN Windows still tries LLMNR/NetBIOS, which the quiet mode drops; a resolved name would show up at the gateway/CT130 (Lockvogel)
if ($x -ne 6 -and $x -ne 28) { "FAIL labdir: Name nicht gesperrt (curl-Ende $x statt 6/28)" }
$a = Nx $c A; $q = Nx $c AAAA; "A $a, AAAA $q"
if ($a -ne "NXDOMAIN") { "FAIL A-Anfrage nicht gesperrt ($a)" }
if ($q -ne "NXDOMAIN") { "FAIL AAAA-Anfrage nicht gesperrt ($q)" }
'
