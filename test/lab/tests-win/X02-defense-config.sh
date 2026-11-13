ID=X02
TITLE="Abwehr-Konfiguration unter Windows: Dienst startet, Tunnel traegt, kein Absturz"
CONFIG=defense
EXPECT_CANARY=tunnel
NOTE="Das Abwehr-Modul ist unter Windows nicht eingebaut (docs/DEFENSE.md: nur Linux/Android). Eine Konfig mit [defense] (wie Max Security) muss trotzdem geladen werden, der Dienst laeuft, der Tunnel traegt, die Status-Antwort bleibt lesbar. Gemeldet wird, was die API zu /v1/defense und im Status sagt."
CLIENT='
Start-Sleep 5
if ((Get-Service Shunt).Status -ne "Running") { "FAIL Dienst laeuft nicht" }
$raw = & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock http://shuntd/v1/status
if (-not $raw) { "FAIL Status nicht lesbar" } else { $st = $raw | ConvertFrom-Json; "Status-Felder: " + (($st.PSObject.Properties.Name) -join ","); "defense im Status: " + ($st.defense | ConvertTo-Json -Compress -Depth 3); foreach ($t in $st.tunnels) { "Tunnel $($t.name): up=$($t.up)"; if (-not $t.up) { "FAIL Tunnel $($t.name) nicht oben" } } }
$d = (& C:\Windows\System32\curl.exe -s -m 10 -o NUL -w "HTTP=%{http_code}" --unix-socket C:\ProgramData\Shunt\shuntd.sock http://shuntd/v1/defense) -join ""
"GET /v1/defense: " + $d.Substring(0, [Math]::Min(300, $d.Length))
1..4 | ForEach-Object { & C:\lab\labtun.exe -s -m3 -o NUL "http://$_-$c/"; Start-Sleep 1 }
Get-Content C:\ProgramData\Shunt\shuntd.log -Tail 12 | Select-String -Pattern "defense|error|panic|warn" | % { $_.Line }
'
