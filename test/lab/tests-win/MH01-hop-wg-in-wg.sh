ID=MH01
TITLE="Multi-Hop WG in WG: das fremde Netz sieht nur den aeusseren Tunnel"
CONFIG=hop
NOTE="labtun auf tunnel:hop (CT130 wgt1) ueber tunnel:intern (wgt0); unter Windows laut docs/WINDOWS.md noch nie erprobt. Mitschnitt CT130 mit CT130_IF=wgt1 TUNNEL_IP=<Address aus wg-hop-lab-win.conf>. Gateway darf nur CT130:51830 sehen; :51831 am Gateway = innerer Hop am aeusseren vorbei. Der Name der Canary geht ueber Dnscache und den Standardweg (intern, wgt0), am wgt1-Mitschnitt fehlt er deshalb evtl.: dann zaehlt die HTTP-Anfrage."
CLIENT='
function Status { $raw = & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock http://shuntd/v1/status; if (-not $raw) { "FAIL Status ueber die API nicht lesbar (curl.exe --unix-socket)"; return }; $st = $raw | ConvertFrom-Json; foreach ($t in $st.tunnels) { "Tunnel $($t.name): up=$($t.up) via=$($t.via) health=$($t.health.state) error=$($t.error)" }; $script:hop = $st.tunnels | Where-Object { $_.name -eq "hop" } }
Start-Sleep 6
1..5 | ForEach-Object { & C:\lab\labtun.exe -s -m3 -o NUL "http://$_-$c/"; Start-Sleep 1 }
$r = (& C:\lab\labtun.exe -s -m5 http://10.69.0.1/) -join ""
if ($r -notmatch "tunnel=10.69.0.1") { "FAIL Testseite des inneren Hops nicht erreicht ($r)" }
Status
if (-not $hop) { "FAIL Status kennt den Tunnel hop nicht" } elseif ($hop.via -notmatch "^(tunnel:)?intern$") { "FAIL Status zeigt den Hop nicht ueber intern (via=$($hop.via))" }
'
