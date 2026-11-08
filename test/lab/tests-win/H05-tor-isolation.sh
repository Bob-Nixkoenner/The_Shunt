ID=H05
TITLE="Tor-Isolation: zwei Apps bekommen verschiedene Exits"
CONFIG=tor-app
EXPECT_CANARY=any
NOTE="labtun und labdir laufen ueber Tor in zwei Regeln (isolate = app, SOCKS-Benutzer = App). Ihre Exit-IPs (check.torproject.org/api/ip) muessen sich unterscheiden; drei Versuche, weil zwei Kreise zufaellig denselben Exit haben koennen. Ohne Prozess-Trace: tor.exe-Verbindungen werden am Gateway ueber die Relays aus dem Konsens des Clients erlaubt (LABALLOW am Ende der Ausgabe, wie Linux H11). Verbindungen zu Fallback-Verzeichnissen, die nicht im Konsens stehen (nur beim ersten Start von tor), erscheinen als Fund: dann im Bericht nachsehen."
CLIENT='
function Api($p) { & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock "http://shuntd$p" }
function TorReady { for ($i=0; $i -lt 90; $i++) { $s = (Api /v1/status) | ConvertFrom-Json -ErrorAction SilentlyContinue; $t = $s.tunnels | Where-Object { $_.name -eq "tor" }; if ($t -and $t.bootstrap -ge 100) { return $true }; Start-Sleep 2 }; if (-not $s) { Write-Host "FAIL API nicht erreichbar (curl.exe --unix-socket)" }; return $false }
function Consensus { $f = Get-ChildItem C:\ProgramData\Shunt\tor -Recurse -Filter cached-microdesc-consensus -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { Get-Content $f.FullName | Where-Object { $_ -like "r *" } | ForEach-Object { $p = $_ -split " "; "$($p[5]):$($p[6])" } } }
function AllowRelays { $n=0; Consensus | ForEach-Object { "LABALLOW dst:$_/tcp"; $n++ }; if ($n -eq 0) { "Hinweis: kein Konsens gefunden, tor.exe-Verbindungen zaehlen am Gateway als Fund" } }
function ExitIp($app) { $r = (& $app -s -m20 https://check.torproject.org/api/ip) -join ""; if ($r -match "IP.{3}([0-9a-fA-F.:]+)") { $Matches[1] } }
if (-not (TorReady)) { "FAIL tor kam nicht hoch" }
$ok = $false
foreach ($i in 1,2,3) { $a = ExitIp C:\lab\labtun.exe; $b = ExitIp C:\lab\labdir.exe; "Versuch ${i}: labtun $a, labdir $b"; if ($a -and $b -and $a -ne $b) { $ok = $true; break }; Start-Sleep 5 }
if (-not $ok) { "FAIL beide Apps haben denselben Exit (oder keinen)" }
AllowRelays
'
