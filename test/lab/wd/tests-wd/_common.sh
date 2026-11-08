# Gemeinsame Hilfen fuer WD05/WD06 (Test-Dateien sourcen das per $TESTS_DIR).
# wd_install_probe <canary>: Start-Aufgabe (SYSTEM) in der VM, die ab dem Boot alle ~0,5 s Anfragen schickt
# (Canary-Name + 1.1.1.1 per App ohne Regel) und Dienststatus + Ergebnis mit Zeit in C:\lab\bootprobe.log schreibt.
wd_install_probe() {
	client_script "$1" <<'P'
New-Item -ItemType Directory C:\lab -Force | Out-Null
Remove-Item C:\lab\bootprobe.log -ErrorAction SilentlyContinue
Set-Content C:\lab\canary.txt $c
Set-Content C:\lab\bootprobe.ps1 @'
$c=(Get-Content C:\lab\canary.txt).Trim(); $o='C:\lab\bootprobe.log'; $sw=[Diagnostics.Stopwatch]::StartNew()
for ($i=0; $i -lt 400 -and $sw.Elapsed.TotalSeconds -lt 240; $i++) {
  $svc=(Get-Service Shunt -ErrorAction SilentlyContinue).Status
  & C:\lab\labfree.exe -s -m1 -o NUL "http://b$i-$c/" 2>$null
  & C:\lab\labfree.exe -s -m1 -o NUL http://1.1.1.1/ 2>$null; $e=$LASTEXITCODE
  Add-Content $o ("{0} up={1:N0} svc={2} ip_exit={3}" -f (Get-Date -f HH:mm:ss.fff), ((Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds, $svc, $e)
  Start-Sleep -Milliseconds 300
}
'@
schtasks /create /tn WDProbe /sc onstart /ru SYSTEM /rl highest /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\bootprobe.ps1" /f | Out-Null
"Probe-Aufgabe da: " + ((schtasks /query /tn WDProbe | Select -Last 1) -replace "\s+"," ")
$w=0; netsh wfp show filters file=C:\lab\wfp.xml | Out-Null; "WFP-Zeilen mit Shunt vor dem Test: " + (Select-String -Path C:\lab\wfp.xml -Pattern "Shunt" -SimpleMatch | Measure-Object).Count
"Dienst: " + (Get-Service Shunt).Status
P
}
# wd_read_boot: liest nach dem Neustart Ereignisse + Probe-Protokoll, gibt FAIL-Zeilen aus
wd_read_boot() {
	client_script x <<'P'
$b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
"Boot (LastBootUpTime): " + $b.ToString("s") + "   Jetzt: " + (Get-Date -f s)
"HiberbootEnabled: " + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power").HiberbootEnabled + "   hiberfil.sys: " + (Test-Path C:\hiberfil.sys -ErrorAction SilentlyContinue)
"-- Ereignisse (System) seit 20 min vor dem Boot:"
Get-WinEvent -FilterHashtable @{LogName="System"; Id=1074,6005,6006,6008,41,109,7036,7043,7031,7034,27; StartTime=$b.AddMinutes(-20)} -ea 0 | Sort-Object TimeCreated | ? { $_.Id -ne 7036 -or $_.Message -match "Shunt" } | % { $m=($_.Message -replace "\s+"," "); "{0} Id={1} {2}" -f $_.TimeCreated.ToString("s"),$_.Id,$m.Substring(0,[math]::Min(150,$m.Length)) }
"-- Kernel-Boot Startart (Id 27: 0x0 = kalt, 0x1 = Schnellstart, 0x2 = Ruhezustand):"
Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName="Microsoft-Windows-Kernel-Boot"; StartTime=$b.AddMinutes(-2)} -ea 0 | ? { $_.Id -eq 27 } | % { ($_.TimeCreated.ToString("s")) + " " + (($_.Message -replace "\s+"," ")) }
"-- shuntd.log (Zeilen mit started/stopping/kill/Network/error, nach dem Boot):"
Get-ChildItem C:\ProgramData\Shunt\*.log | Sort LastWriteTime | Select -Last 1 | % { Get-Content $_.FullName | Select-String "started|stopping|kill|unreachable|error|v0\." | Select -Last 12 | % { $_.Line } }
"-- Probe-Protokoll:"
if (-not (Test-Path C:\lab\bootprobe.log)) { "FAIL Probe-Protokoll fehlt (Aufgabe lief nicht)"; return }
$l=Get-Content C:\lab\bootprobe.log
"Probe-Zeilen: " + $l.Count; "erste: " + $l[0]; "letzte: " + $l[-1]
$run=($l | ? { $_ -match "svc=Running" } | Select -First 1); "erste Zeile mit Dienst Running: " + $run
$nr=$l | ? { $_ -notmatch "svc=Running" }
"Zeilen mit Dienst nicht Running: " + @($nr).Count + "  (Status: " + ((($nr | % { ($_ -split " ")[2] }) | Group-Object | % { "$($_.Name)=$($_.Count)" }) -join ", ") + ")"
$leak=$nr | ? { $_ -match "ip_exit=0" }
if ($leak) { "FAIL " + @($leak).Count + " Anfragen nach 1.1.1.1 kamen OHNE laufenden Dienst durch; erste: " + $leak[0] }
$l | Select -First 6
P
}
