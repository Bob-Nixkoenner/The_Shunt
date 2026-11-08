ID=H06
TITLE="Tor mit obfs4-Bruecken: tor.exe/lyrebird.exe sprechen nur mit Bruecken, nie mit Relays"
CONFIG=tor-bridge
EXPECT_CANARY=any
# the built-in obfs4 bridges (internal/tunnel/tor_bridges.go), as in tests/H06
ALLOW=(dst:146.57.248.225:22/tcp dst:209.148.46.65:443/tcp dst:212.83.43.74:443/tcp dst:212.83.43.95:443/tcp dst:37.218.245.14:38224/tcp dst:45.145.95.6:27015/tcp dst:51.222.13.177:80/tcp)
NOTE="Eingebaute obfs4-Bruecken. Am Gateway duerfen nur die Bruecken-Adressen (ALLOW) und WireGuard auftauchen, also keine Relays (hier ohne LABALLOW, das ist der Test). Im Client: keine bestehende TCP-Verbindung von tor.exe/lyrebird.exe zu einer Adresse aus dem Konsens (Get-NetTCPConnection), und Web ueber Tor geht. Aendert Tor die eingebauten Bruecken, ALLOW anpassen."
CLIENT='
function Api($p) { & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock "http://shuntd$p" }
function TorReady { for ($i=0; $i -lt 90; $i++) { $s = (Api /v1/status) | ConvertFrom-Json -ErrorAction SilentlyContinue; $t = $s.tunnels | Where-Object { $_.name -eq "tor" }; if ($t -and $t.bootstrap -ge 100) { return $true }; Start-Sleep 2 }; if (-not $s) { Write-Host "FAIL API nicht erreichbar (curl.exe --unix-socket)" }; return $false }
function Consensus { $f = Get-ChildItem C:\ProgramData\Shunt\tor -Recurse -Filter cached-microdesc-consensus -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { Get-Content $f.FullName | Where-Object { $_ -like "r *" } | ForEach-Object { $p = $_ -split " "; "$($p[5]):$($p[6])" } } }
function AllowRelays { $n=0; Consensus | ForEach-Object { "LABALLOW dst:$_/tcp"; $n++ }; if ($n -eq 0) { "Hinweis: kein Konsens gefunden, tor.exe-Verbindungen zaehlen am Gateway als Fund" } }
if (-not (TorReady)) { "FAIL tor kam ueber die Bruecken nicht hoch" }
$ok = $false; foreach ($i in 1,2,3) { if (((& C:\lab\labtun.exe -s -m40 https://check.torproject.org/api/ip) -join "") -match "IsTor.:true") { $ok = $true; break }; Start-Sleep 10 }
if (-not $ok) { "FAIL Web geht nicht ueber Tor" }
$relays = @(Consensus | ForEach-Object { ($_ -split ":")[0] }) | Sort-Object -Unique
if (-not $relays) { "Hinweis: kein Konsens gefunden, Abgleich entfaellt" } else {
  $ids = @(Get-Process tor,lyrebird -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
  $peers = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -in $ids -and $_.RemoteAddress -notmatch "^(127\.|::1)" } | ForEach-Object { $_.RemoteAddress }) | Sort-Object -Unique
  "tor/lyrebird verbunden mit: $($peers -join " ")"
  foreach ($x in $peers) { if ($relays -contains $x) { "FAIL Verbindung zu normalem Relay: $x" } }
}
'
