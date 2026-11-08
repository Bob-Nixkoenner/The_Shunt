ID=H08
TITLE=".onion-Namen gehen nie an einen normalen DNS-Server"
CONFIG=tor-app
EXPECT_CANARY=none
NOTE="Die Canary wird als <canary>.onion gefragt: von einer Tor-App (labtun), einer App ohne Regel (labfree, Standardweg WireGuard), per Resolve-DnsName ueber Dnscache und direkt an den Shunt-DNS 10.111.0.53; danach wird tor.exe beendet. Sie darf weder am Gateway (DNS) noch am Tunnel-Ausgang (CT130) auftauchen. Ohne Prozess-Trace: tor.exe-Verbindungen werden am Gateway ueber die Relays aus dem Konsens des Clients erlaubt (LABALLOW am Ende der Ausgabe, wie Linux H11). Verbindungen zu Fallback-Verzeichnissen, die nicht im Konsens stehen (nur beim ersten Start von tor), erscheinen als Fund: dann im Bericht nachsehen."
CLIENT='
function Api($p) { & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock "http://shuntd$p" }
function TorReady { for ($i=0; $i -lt 90; $i++) { $s = (Api /v1/status) | ConvertFrom-Json -ErrorAction SilentlyContinue; $t = $s.tunnels | Where-Object { $_.name -eq "tor" }; if ($t -and $t.bootstrap -ge 100) { return $true }; Start-Sleep 2 }; if (-not $s) { Write-Host "FAIL API nicht erreichbar (curl.exe --unix-socket)" }; return $false }
function Consensus { $f = Get-ChildItem C:\ProgramData\Shunt\tor -Recurse -Filter cached-microdesc-consensus -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { Get-Content $f.FullName | Where-Object { $_ -like "r *" } | ForEach-Object { $p = $_ -split " "; "$($p[5]):$($p[6])" } } }
function AllowRelays { $n=0; Consensus | ForEach-Object { "LABALLOW dst:$_/tcp"; $n++ }; if ($n -eq 0) { "Hinweis: kein Konsens gefunden, tor.exe-Verbindungen zaehlen am Gateway als Fund" } }
if (-not (TorReady)) { "FAIL tor kam nicht hoch" }
$o = "$c.onion"
& C:\lab\labtun.exe -s -m6 -o NUL "http://$o/" 2>$null; "labtun: $LASTEXITCODE"
& C:\lab\labfree.exe -s -m6 -o NUL "http://$o/" 2>$null; "labfree: $LASTEXITCODE"
Resolve-DnsName $o -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
Resolve-DnsName "s-$o" -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
AllowRelays
Stop-Process -Name tor -Force -ErrorAction SilentlyContinue; Start-Sleep 3
'
