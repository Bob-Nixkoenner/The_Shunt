ID=FL08
TITLE="DNS-Filter: Umgehung über DoH zu einer IP (curl --doh-url)"
CONFIG=filter-lab
EXPECT_CANARY=none
PREP='Set-Content -Encoding ascii C:\ProgramData\Shunt\lab-filter.txt "||shuntlab.test^"'
NOTE="Ein Programm, das DoH selbst spricht (hier labtun = curl.exe zu 1.1.1.1), sieht den Filter nicht (block_doh sperrt nur Namen bekannter DoH-Server, keine IP). Geht die Anfrage durch, taucht der Canary am Tunnel-Ausgang auf: das ist dann ein dokumentierter Fund wie unter Linux, kein Fehler im Test."
CLIENT='
& C:\lab\labtun.exe -s -m6 --doh-url https://1.1.1.1/dns-query -o NUL "http://$c/"; "curl-Ende: $LASTEXITCODE"
'
