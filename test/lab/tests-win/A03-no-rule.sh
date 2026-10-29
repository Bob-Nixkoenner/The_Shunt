ID=A03
TITLE="App ohne Regel nimmt den Standardweg (Tunnel)"
CLIENT='
& C:\lab\labfree.exe -s -m8 -o NUL "http://$c/"
$ip = & C:\lab\labfree.exe -s -m8 http://ifconfig.me/ip; "Ausgangs-IP: $ip"
if ($ip -ne "185.216.213.230") { "FAIL Ausgangs-IP $ip statt CT130" }
'
