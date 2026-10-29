ID=A02
TITLE="App auf direkt geht am Tunnel vorbei"
EXPECT_CANARY=gw
ALLOW=(comm:* dns)
NOTE="Direkt heißt: das fremde Netz darf diese App und ihre DNS-Anfragen sehen."
CLIENT='
& C:\lab\labdir.exe -s -m8 -o NUL "http://$c/"
$ip = & C:\lab\labdir.exe -4 -s -m8 http://ifconfig.me/ip; "Ausgangs-IP: $ip"
if (-not $ip -or $ip -eq "185.216.213.230") { "FAIL direkte App kam über den Tunnel raus ($ip)" }
'
