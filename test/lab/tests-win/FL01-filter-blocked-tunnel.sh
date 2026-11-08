ID=FL01
TITLE="DNS-Filter: gesperrter Name verlässt das Gerät nicht (App im Tunnel)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='Set-Content -Encoding ascii C:\ProgramData\Shunt\lab-filter.txt "||shuntlab.test^"'
NOTE="Lokale Liste sperrt *.shuntlab.test (Windows: nur die Stufe default, gilt fuer alle Apps). Der Canary darf weder am Gateway noch am Tunnel-Ausgang auftauchen. Geprueft: labtun holt http://<canary>/ (Namen loest unter Windows Dnscache auf, curl muss mit 'Name nicht aufloesbar', Ende 6, scheitern) und eine A/AAAA-Abfrage direkt an den Shunt-DNS 10.111.0.53 muss NXDOMAIN (9003) bekommen."
CLIENT='
function Nx($n,$t) { $r = Resolve-DnsName $n -Type $t -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue -ErrorVariable e; if ($r) { "Antwort" } elseif ($e -and $e[0].Exception.NativeErrorCode -eq 9003) { "NXDOMAIN" } else { "anders: " + $e[0].Exception.Message } }
& C:\lab\labtun.exe -s -m6 -o NUL "http://$c/"; $x=$LASTEXITCODE; "labtun curl-Ende: $x"
if ($x -ne 6) { "FAIL labtun: Name nicht gesperrt (curl-Ende $x statt 6)" }
$a = Nx $c A; $q = Nx $c AAAA; "A $a, AAAA $q"
if ($a -ne "NXDOMAIN") { "FAIL A-Anfrage nicht gesperrt ($a)" }
if ($q -ne "NXDOMAIN") { "FAIL AAAA-Anfrage nicht gesperrt ($q)" }
'
