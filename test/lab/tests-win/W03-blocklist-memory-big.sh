ID=W03
TITLE="Blocklisten-Speicher: knapp 5 Mio. synthetische Namen in drei lokalen Listen"
CONFIG=filter-big
EXPECT_CANARY=any
NOTE="Erzeugt im Gast drei Listen mit zusammen 4,8 Mio. Namen (Adblock-Format; eine Liste ueber 64 MB wird abgeschnitten, deshalb drei), startet den Dienst neu und misst WorkingSet/Peak von shuntd-win.exe. Danach muss ein Name aus der Liste NXDOMAIN bekommen und ein anderer nicht. Ziel: deutlich unter 1 GB."
PREP='
Add-Type -TypeDefinition @"
using System.IO;
public static class G { public static void Run(string f, int from, int n) { using (var w = new StreamWriter(f)) { for (int i = from; i < from + n; i++) w.WriteLine("||h" + i.ToString("x") + ".bigfilter.test^"); } } }
"@
foreach ($k in 0,1,2) { [G]::Run("C:\ProgramData\Shunt\big-filter$($k+1).txt", $k * 1600000, 1600000) }
"big-filter: " + [int]((Get-ChildItem C:\ProgramData\Shunt\big-filter?.txt | Measure-Object Length -Sum).Sum/1MB) + " MB"
'
CLIENT='
Stop-Service Shunt -Force -WarningAction SilentlyContinue
Start-Service Shunt -WarningAction SilentlyContinue
foreach ($t in 40,40) {
  Start-Sleep $t
  $p = Get-Process shuntd-win
  "RSS ws=" + [int]($p.WorkingSet64/1MB) + " MB, peak=" + [int]($p.PeakWorkingSet64/1MB) + " MB, private=" + [int]($p.PrivateMemorySize64/1MB) + " MB"
}
function Nx($n) { $r = Resolve-DnsName $n -Type A -Server 10.111.0.53 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue -ErrorVariable e; if ($r) { "Antwort" } elseif ($e -and $e[0].Exception.NativeErrorCode -eq 9003) { "NXDOMAIN" } else { "anders" } }
$a = Nx "h493dff.bigfilter.test"; "gelistet (letzter Name der dritten Liste): $a"
if ($a -ne "NXDOMAIN") { "FAIL gelisteter Name nicht gesperrt" }
$b = Nx "example.com"; "nicht gelistet (example.com): $b"
if ($b -ne "Antwort") { "FAIL ungelisteter Name wird nicht beantwortet ($b)" }
if ($p.PeakWorkingSet64 -gt 1GB) { "FAIL Peak ueber 1 GB" }
Get-Content C:\ProgramData\Shunt\shuntd.log -Tail 8 | Select-String "dns filter"
Remove-Item C:\ProgramData\Shunt\big-filter?.txt -ErrorAction SilentlyContinue
'
