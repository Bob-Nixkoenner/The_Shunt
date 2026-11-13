ID=W02
TITLE="Blocklisten-Speicher: Arbeitsspeicher des Dienstes mit den echten Standardlisten"
CONFIG=filter
EXPECT_CANARY=any
NOTE="Leerer Listen-Cache, Dienst neu starten, die Standardlisten (Stufe normal) kommen ueber den Tunnel. Gemessen werden WorkingSet und Peak von shuntd-win.exe nach 60 s und nach 120 s. Ziel: deutlich unter 1 GB."
CLIENT='
Stop-Service Shunt -Force -WarningAction SilentlyContinue
Remove-Item -Recurse -Force C:\ProgramData\Shunt\blocklists -ErrorAction SilentlyContinue
Start-Service Shunt -WarningAction SilentlyContinue
foreach ($t in 60,60) {
  Start-Sleep $t
  $p = Get-Process shuntd-win
  "RSS ws=" + [int]($p.WorkingSet64/1MB) + " MB, peak=" + [int]($p.PeakWorkingSet64/1MB) + " MB, private=" + [int]($p.PrivateMemorySize64/1MB) + " MB"
}
$n = (Get-ChildItem C:\ProgramData\Shunt\blocklists -ErrorAction SilentlyContinue | Measure-Object Length -Sum)
"lists: " + $n.Count + ", " + [int]($n.Sum/1MB) + " MB on disk"
if ($p.PeakWorkingSet64 -gt 1GB) { "FAIL Peak ueber 1 GB" }
if ($n.Count -eq 0) { "FAIL keine Listen geladen" }
Get-Content C:\ProgramData\Shunt\shuntd.log -Tail 4
'
