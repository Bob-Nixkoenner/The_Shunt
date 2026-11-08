ID=M05
TITLE="Regel im laufenden Betrieb umschalten: Tunnel -> direkt -> Tunnel"
CONFIG=m-toggle
EXPECT_CANARY=any
ALLOW=(dst:34.160.111.145:80/tcp)
PREP='Copy-Item -Force C:\Windows\System32\curl.exe C:\lab\labtog.exe'
NOTE="labtog startet dauernd neu und fragt ifconfig.me/ip. Tunnel = Ausgangs-IP von CT130 (185.216.213.230), direkt = jede andere Antwort. Anders als Linux nicht ueber 10.77.0.1: unter Windows gehen LAN-Ziele immer direkt. Nach jedem reload (API) muss der Weg der Regel folgen, Gnadenfrist 3 s. Erlaubt am Gateway: labtogs direkte Abfrage von ifconfig.me (ALLOW mit der Adresse vom 08.11.; hat ifconfig.me eine andere, steht der Zugriff als Fund im Bericht und ist dann gewollt)."
CLIENT='
function Way { $ip = (& C:\lab\labtog.exe -s -m5 http://ifconfig.me/ip) 2>$null; if ($ip -eq "185.216.213.230") { "tunnel" } elseif ($ip) { "direct" } else { "none" } }
function SetRoute($r) {
  $f="C:\ProgramData\Shunt\shunt.toml"; $txt = Get-Content -Raw $f
  $txt = [regex]::Replace($txt, "(?s)(name = `"lab: toggle`".*?route = )`"[^`"]*`"", "`$1`"$r`"")
  [IO.File]::WriteAllText($f, $txt)
  & C:\Windows\System32\curl.exe -s -m 10 --unix-socket C:\ProgramData\Shunt\shuntd.sock -X POST http://shuntd/v1/reload | Out-Null
  if ($LASTEXITCODE -ne 0) { "FAIL reload ueber die API ging nicht" }
  Start-Sleep 3
}
$w = Way; "tunnel: $w"; if ($w -ne "tunnel") { "FAIL Ausgangszustand nicht Tunnel: $w" }
foreach ($round in 1,2) {
  SetRoute "direct"; $w = Way; "direct: $w"; if ($w -ne "direct") { "FAIL nach direct: Weg $w, Regel greift nicht" }
  SetRoute "tunnel:intern"; $w = Way; "tunnel: $w"; if ($w -ne "tunnel") { "FAIL zurueck auf Tunnel: Weg $w" }
}
'
