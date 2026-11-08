ID=MH03
TITLE="Multi-Hop: innerer Tunnel kommt nie hoch (falscher Schluessel): kein Rueckfall auf den ersten Hop"
CONFIG=hop
HOP_BADKEY=1
EXPECT_CANARY=none
NOTE="tunnels\\hop.conf mit falschem Server-Schluessel (winclient.sh). labtun auf tunnel:hop bekommt nichts; die Anfrage darf weder im Klartext noch auf wgt0 (Rueckfall auf Hop A) noch am Gateway erscheinen. Aufruf: CT130_IF=wgt0 CLIENT_OS=windows lab.sh run MH03. Achtung: der Name der Canary geht unter Windows ueber Dnscache und den Standardweg (intern = wgt0); taucht nur die DNS-Anfrage am wgt0 auf, ist das kein Rueckfall, nur eine HTTP-Anfrage dort waere einer (im Bericht pruefen)."
CLIENT='
function Status { $raw = & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock http://shuntd/v1/status; if (-not $raw) { "FAIL Status ueber die API nicht lesbar (curl.exe --unix-socket)"; return }; $st = $raw | ConvertFrom-Json; foreach ($t in $st.tunnels) { "Tunnel $($t.name): up=$($t.up) via=$($t.via) health=$($t.health.state) error=$($t.error)" }; $script:hop = $st.tunnels | Where-Object { $_.name -eq "hop" } }
Start-Sleep 6
1..8 | ForEach-Object { & C:\lab\labtun.exe -s -m2 -o NUL "http://$_-$c/"; if ($LASTEXITCODE -eq 0) { "FAIL labtun kam durch (innerer Hop tot)" }; Start-Sleep 1 }
& C:\lab\labtun.exe -s -m3 -o NUL http://1.1.1.1/; if ($LASTEXITCODE -eq 0) { "FAIL labtun erreicht 1.1.1.1 (innerer Hop tot)" }
Status
if ($hop -and $hop.health.state -eq "ok") { "FAIL Status zeigt den Hop ohne Handshake als ok" }
'
