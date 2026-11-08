ID=MH08
TITLE="Multi-Hop live umbauen: via entfernen und wieder setzen, nichts im Klartext"
CONFIG=hop
EXPECT_CANARY=any
ALLOW=(dst:10.66.0.1:51831/udp)
PREP='Copy-Item -Force C:\Windows\System32\curl.exe C:\lab\labtog.exe'
NOTE="Ohne via ist der Hop ein normaler Tunnel: sein WireGuard-Handshake zum Endpunkt 10.66.0.1:51831 geht dann direkt (erlaubt, verschluesselt, kein App-Verkehr). labtog (Regel auf tunnel:hop) fragt dauernd. Zwischendurch wird via aus C:\ProgramData\Shunt\shunt.toml genommen und wieder gesetzt (reload ueber die API). In der Luecke darf nichts im Klartext auftauchen; danach muss der Hop wieder tragen. Ohne Prozess-Trace: unter Linux erlaubt ALLOW comm:labtog, hier nicht moeglich, also zaehlt jeder Klartext."
CLIENT='
function HopOk { ((& C:\lab\labtog.exe -s -m4 http://10.69.0.1/) -join "") -match "tunnel=10.69.0.1" }
function SetVia($line) {
  $f="C:\ProgramData\Shunt\shunt.toml"; $txt = Get-Content -Raw $f
  $txt = [regex]::Replace($txt, "(?m)^(via = .*|# via entfernt)\r?$", $line)
  [IO.File]::WriteAllText($f, $txt)
  & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock -X POST http://shuntd/v1/reload | Out-Null
  if ($LASTEXITCODE -ne 0) { "FAIL reload ueber die API ging nicht" }
  Start-Sleep 4
}
Start-Sleep 6; if (-not (HopOk)) { "FAIL Ausgangszustand: Hop traegt nicht" }
if (-not (Select-String -Quiet -Pattern "^via = " C:\ProgramData\Shunt\shunt.toml)) { "FAIL Testaufbau: via fehlt in der Config" }
foreach ($round in 1,2) {
  SetVia "# via entfernt"
  foreach ($i in 1,2,3) { & C:\lab\labtog.exe -s -m2 -o NUL "http://l$round$i-$c/" }
  SetVia "via = `"tunnel:intern`""; Start-Sleep 4
  if (-not (HopOk)) { "FAIL Runde ${round}: Hop traegt nach dem Zurueckschalten nicht" }
}
'
