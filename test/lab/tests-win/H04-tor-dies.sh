ID=H04
TITLE="Tor als App-Weg: tor.exe haengt oder stirbt, die App geht nie direkt"
CONFIG=tor-app
EXPECT_CANARY=none
NOTE="labtun laeuft ueber Tor, alles andere ueber WireGuard. tor.exe wird angehalten (NtSuspendProcess, braucht Debug-Recht des Admins) und beendet (der Dienst startet es mit Pause neu). labtun darf in beiden Faellen weder die Canary noch 1.1.1.1 erreichen, auch nicht direkt. Die Namen der Tor-App gehen durch Tor (der Dienst liest aus den DNS-Client-Ereignissen, wer gefragt hat): taucht die Canary am CT130 auf, ist das ein Fund. Ohne Prozess-Trace: tor.exe-Verbindungen werden am Gateway ueber die Relays aus dem Konsens des Clients erlaubt (LABALLOW am Ende der Ausgabe, wie Linux H11). Verbindungen zu Fallback-Verzeichnissen, die nicht im Konsens stehen (nur beim ersten Start von tor), erscheinen als Fund: dann im Bericht nachsehen."
CLIENT='
function Api($p) { & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock "http://shuntd$p" }
function TorReady { for ($i=0; $i -lt 90; $i++) { $s = (Api /v1/status) | ConvertFrom-Json -ErrorAction SilentlyContinue; $t = $s.tunnels | Where-Object { $_.name -eq "tor" }; if ($t -and $t.bootstrap -ge 100) { return $true }; Start-Sleep 2 }; if (-not $s) { Write-Host "FAIL API nicht erreichbar (curl.exe --unix-socket)" }; return $false }
function Consensus { $f = Get-ChildItem C:\ProgramData\Shunt\tor -Recurse -Filter cached-microdesc-consensus -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { Get-Content $f.FullName | Where-Object { $_ -like "r *" } | ForEach-Object { $p = $_ -split " "; "$($p[5]):$($p[6])" } } }
function AllowRelays { $n=0; Consensus | ForEach-Object { "LABALLOW dst:$_/tcp"; $n++ }; if ($n -eq 0) { "Hinweis: kein Konsens gefunden, tor.exe-Verbindungen zaehlen am Gateway als Fund" } }
Add-Type -Namespace Lab -Name Nt -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("ntdll.dll")] public static extern int NtSuspendProcess(System.IntPtr h);
[System.Runtime.InteropServices.DllImport("ntdll.dll")] public static extern int NtResumeProcess(System.IntPtr h);
"@
if (-not (TorReady)) { "FAIL tor kam nicht hoch" }
& C:\lab\labtun.exe -s -m20 -o NUL https://check.torproject.org/; if ($LASTEXITCODE -ne 0) { "FAIL labtun erreicht nichts ueber Tor" }
[System.Diagnostics.Process]::EnterDebugMode()
$p = Get-Process tor -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { "FAIL kein tor.exe gefunden" } else {
  $r = [Lab.Nt]::NtSuspendProcess($p.Handle); "Suspend: $r"; Start-Sleep 1
  & C:\lab\labtun.exe -s -m6 -o NUL "http://$c/"; if ($LASTEXITCODE -eq 0) { "FAIL Canary erreichbar, waehrend tor haengt" }
  & C:\lab\labtun.exe -s -m6 -o NUL http://1.1.1.1/; if ($LASTEXITCODE -eq 0) { "FAIL 1.1.1.1 erreichbar, waehrend tor haengt" }
  [void][Lab.Nt]::NtResumeProcess($p.Handle)
}
AllowRelays
Stop-Process -Name tor -Force -ErrorAction SilentlyContinue; "tor beendet $(Get-Date -Format HH:mm:ss.fff)"; Start-Sleep 1
& C:\lab\labtun.exe -s -m6 -o NUL "http://k-$c/"; if ($LASTEXITCODE -eq 0) { "FAIL Canary erreichbar nach tor-Ende" }
$t0 = Get-Date -Format HH:mm:ss.fff
$w = & C:\lab\labtun.exe -s -m6 -o NUL -w "http=%{http_code} ip=%{remote_ip}:%{remote_port} connect=%{time_connect}s total=%{time_total}s" http://1.1.1.1/; $rc = $LASTEXITCODE
"1.1.1.1 nach tor-Ende ab $t0 : rc=$rc $w"
if ($rc -eq 0) { "FAIL 1.1.1.1 erreichbar nach tor-Ende"; $s = (Api /v1/status) | ConvertFrom-Json -ErrorAction SilentlyContinue; $s.tunnels | Where-Object { $_.name -eq "tor" } | ForEach-Object { "Tor-Status: up=$($_.up) bootstrap=$($_.bootstrap) error=$($_.error)" }; Get-Process tor -ErrorAction SilentlyContinue | ForEach-Object { "tor.exe pid $($_.Id) seit $(Get-Date $_.StartTime -Format HH:mm:ss.fff)" } }
Start-Sleep 15; if (-not (TorReady)) { "FAIL tor startet nicht wieder" }
'
