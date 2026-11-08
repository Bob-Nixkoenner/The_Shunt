ID=A02
TITLE="App auf direkt geht am Tunnel vorbei"
# Windows: the DNS client service (svchost) asks for the app, so The Shunt sees svchost.exe as the
# owner of the query, not labdir.exe; the name goes the default route (tunnel). The traffic of the
# app itself is direct (checked below). Not a leak: a limit of Windows name resolution.
EXPECT_CANARY=tunnel
ALLOW=(comm:* dns)
NOTE="Direkt heißt unter Windows: der Datenverkehr der App geht direkt; ihr Name wird vom Windows-DNS-Dienst (svchost) aufgelöst und folgt der Standard-Route (Tunnel). Das fremde Netz sieht den Namen nicht."
CLIENT='
& C:\lab\labdir.exe -s -m8 -o NUL "http://$c/"
$ip = & C:\lab\labdir.exe -4 -s -m8 http://ifconfig.me/ip; "Ausgangs-IP: $ip"
if (-not $ip -or $ip -eq "185.216.213.230") { "FAIL direkte App kam über den Tunnel raus ($ip)" }
'
