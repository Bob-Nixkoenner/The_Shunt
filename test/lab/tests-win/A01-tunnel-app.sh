ID=A01
TITLE="App auf dem Tunnel geht nur über CT130 raus"
CONFIG=base
CLIENT='
& C:\lab\labtun.exe -s -m8 -o NUL "http://$c/"
$ip = & C:\lab\labtun.exe -s -m8 http://ifconfig.me/ip; "Ausgangs-IP: $ip"
if ($ip -ne "185.216.213.230") { "FAIL Ausgangs-IP $ip statt 185.216.213.230 (CT130)" }
'
