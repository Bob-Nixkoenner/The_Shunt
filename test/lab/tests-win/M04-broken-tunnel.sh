ID=M04
TITLE="Tunnel kommt nie hoch (falscher Endpunkt, falscher Schluessel): nie direkt"
CONFIG=m-broken
EXPECT_CANARY=none
ALLOW=(dst:192.0.2.77:51820/udp)
# dead.conf: endpoint nobody answers; badkey.conf: random server key (never a handshake).
# Copies inherit the admin-only rights of tunnels\. labtog.exe = another copy of curl.exe.
PREP='
$d="C:\ProgramData\Shunt\tunnels"
(Get-Content "$d\intern.conf") -replace "^Endpoint *=.*","Endpoint = 192.0.2.77:51820" | Set-Content -Encoding ascii "$d\dead.conf"
$k=[Convert]::ToBase64String([byte[]](1..32 | ForEach-Object { Get-Random -Maximum 256 }))
(Get-Content "$d\intern.conf") -replace "^PublicKey *=.*","PublicKey = $k" | Set-Content -Encoding ascii "$d\badkey.conf"
Copy-Item -Force C:\Windows\System32\curl.exe C:\lab\labtog.exe
'
NOTE="labtun-Regel zeigt auf einen Tunnel mit totem Endpunkt, labtog auf einen mit falschem Schluessel. Erwartung: blockiert, im Status (API, curl.exe --unix-socket) nicht als ok, nichts im Klartext. Der Name der Canary geht ueber Dnscache und den Standardweg (Tunnel intern): ohne Prozess-Trace ist am CT130 nicht zu unterscheiden, wer gefragt hat, deshalb fragt der Test nur per HTTP (Name wird trotzdem aufgeloest) und EXPECT_CANARY=none prueft nur Gateway/Klartext. Hinweis: kommt die Canary am CT130 an, ist das die Namensaufloesung ueber den Standardweg, kein Leck (Ergebnis im Bericht pruefen)."
CLIENT='
Start-Sleep 4
1..8 | ForEach-Object {
  & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"; if ($LASTEXITCODE -eq 0) { "FAIL labtun kam durch (toter Tunnel)" }
  & C:\lab\labtog.exe -s -m2 -o NUL "http://t$_-$c/"; if ($LASTEXITCODE -eq 0) { "FAIL labtog kam durch (falscher Schluessel)" }
  & C:\lab\labtun.exe -s -m2 -o NUL http://1.1.1.1/; if ($LASTEXITCODE -eq 0) { "FAIL labtun erreicht 1.1.1.1 (toter Tunnel)" }
  Start-Sleep -Milliseconds 500
}
$raw = & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock http://shuntd/v1/status
if (-not $raw) { "FAIL Status ueber die API nicht lesbar (curl.exe --unix-socket)" } else {
  $st = $raw | ConvertFrom-Json
  foreach ($t in $st.tunnels) { "Tunnel $($t.name): up=$($t.up) health=$($t.health.state) error=$($t.error)" }
  foreach ($t in $st.tunnels | Where-Object { $_.name -in "dead","badkey" }) {
    if ($t.health.state -eq "ok") { "FAIL Status zeigt $($t.name) ohne Handshake als ok" }
  }
}
'
