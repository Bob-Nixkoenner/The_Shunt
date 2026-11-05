ID=U01
TITLE="Update per Setup.exe ueber die laufende Installation (Tunnel aktiv): nichts im Klartext, Dienst und Tunnel danach wieder da"
# the lab app on the tunnel legitimately shows its canary at the tunnel exit
UPDATE_SETUP=${UPDATE_SETUP:-}
NOTE="Setup (neuere Version, per UPDATE_SETUP=<Pfad>) laeuft still (/VERYSILENT) ueber die laufende Installation, waehrend die Tunnel-App jede Sekunde Anfragen schickt. Erwartung: Waehrend des Updates kommt nichts im Klartext raus (Kill-Switch/Dienst), danach laeuft der Dienst mit der neuen Version, die Konfiguration ist unveraendert und die Tunnel-App geht wieder ueber den Tunnel."
during() {
	[[ -f $UPDATE_SETUP ]] || { echo "FAIL kein UPDATE_SETUP"; return; }
	client 'Remove-Item C:\lab\update-done -ErrorAction SilentlyContinue'
	sleep 12
	client_cp_to "$UPDATE_SETUP" 'C:\lab\update-setup.exe' >/dev/null
	client 'Get-FileHash C:\ProgramData\Shunt\shunt.toml | Select -Expand Hash > C:\lab\cfg-before.txt; (Select-String -Path C:\ProgramData\Shunt\*.log -Pattern "shuntd-win v[0-9A-Za-z.-]+" | Select -Last 1).Matches.Value > C:\lab\ver-before.txt'
	echo "Version vorher: $(client 'Get-Content C:\lab\ver-before.txt' | tail -1)"
	client 'Start-Process C:\lab\update-setup.exe -ArgumentList "/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/CLOSEAPPLICATIONS","/LOG=C:\lab\update.log" -Wait; "setup exit: $LASTEXITCODE"'
	client 'New-Item C:\lab\update-done -ItemType File -Force | Out-Null'
	echo "Setup fertig"
	for i in $(seq 60); do [[ $(client 'Test-Path C:\lab\u01-end') == True ]] && break; sleep 10; done
	client 'Get-Content C:\lab\u01.out'
}
CLIENT='
# The measuring loop runs detached from the guest-control session (Win32_Process.Create): the
# Setup stops the service and closes processes, a loop inside this session was killed by it.
$sb = {
& {
$ok=0;$fail=0
for ($i=0;$i -lt 60;$i++) {
  $ip = (& C:\lab\labtun.exe -s -m3 http://ifconfig.me/ip) 2>$null
  if ($ip -eq "185.216.213.230") { $ok++ } elseif ($ip) { "FAIL Tunnel-App meldet Ausgangs-IP $ip (nicht der Tunnel)" } else { $fail++ }
  & C:\lab\labtun.exe -s -m1 -o NUL "http://u$i-$c/" 2>$null
  Resolve-DnsName "u$i-$c" -Server 10.77.0.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep 1
}
$w=0; while (-not (Test-Path C:\lab\update-done) -and $w -lt 300) { Start-Sleep 2; $w+=2 }
"Anfragen: $ok ueber den Tunnel, $fail ohne Antwort (Update-Luecke)"
Start-Sleep 15
$svc=(Get-Service Shunt).Status; "Dienst: $svc"; if ($svc -ne "Running") { "FAIL Dienst laeuft nach dem Update nicht" }
$ver=(Select-String -Path C:\ProgramData\Shunt\*.log -Pattern "shuntd-win v[0-9A-Za-z.-]+" | Select -Last 1).Matches.Value; "Version nachher: $ver"
$before=(Get-Content C:\lab\ver-before.txt -ErrorAction SilentlyContinue); if ($before -and $ver -eq $before) { "FAIL Version unveraendert ($ver)" }
$h=(Get-FileHash C:\ProgramData\Shunt\shunt.toml).Hash; $hb=(Get-Content C:\lab\cfg-before.txt -ErrorAction SilentlyContinue); if ($hb -and $h -ne $hb) { "FAIL Konfiguration hat sich geaendert" }
$ip=(& C:\lab\labtun.exe -s -m8 http://ifconfig.me/ip); "Ausgangs-IP nachher: $ip"; if ($ip -ne "185.216.213.230") { "FAIL Tunnel-App nach dem Update nicht ueber den Tunnel" }
$p=(Get-Process shuntd-win -ErrorAction SilentlyContinue | Measure-Object).Count; if ($p -ne 1) { "FAIL shuntd-win Prozesse: $p" }
} *> C:\lab\u01.out
New-Item C:\lab\u01-end -ItemType File -Force | Out-Null
}
Remove-Item C:\lab\u01.out,C:\lab\u01-end -ErrorAction SilentlyContinue
Set-Content C:\lab\u01-mon.ps1 ("`$c=`"$c`"`r`n" + $sb.ToString())
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\u01-mon.ps1"} | Out-Null
"Messschleife gestartet"
'
