ID=M03
TITLE="Umbau-Lecks: reload und Dienst-Neustart waehrend Apps senden"
EXPECT_CANARY=any
NOTE="Waehrend labtun/labfree dauernd senden: fuenfmal reload ueber die API (curl.exe --unix-socket, geht die API nicht, steht das im during.log), dreimal Restart-Service Shunt. Kein Paket darf direkt raus (labfree hat Standardweg Tunnel). Ohne Prozess-Trace: jeder Klartext am Gateway zaehlt, auch Windows-eigener Verkehr in der Neustart-Luecke (dann im Bericht nachsehen, wer es war)."
during() {
	sleep 4
	local i
	for i in 1 2 3 4 5; do
		client '& C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock -X POST http://shuntd/v1/reload' || echo "reload $i: API nicht erreichbar"
		sleep 1.5
	done
	for i in 1 2 3; do client 'Restart-Service Shunt -WarningAction SilentlyContinue' || true; sleep 3; done
}
CLIENT='
1..50 | ForEach-Object {
  & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"
  & C:\lab\labfree.exe -s -m2 -o NUL http://1.1.1.1/
  Resolve-DnsName "d$_-$c" -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep -Milliseconds 500
}
'
