ID=W03
TITLE="Blocklisten-Speicher: 5 Mio. synthetische Namen in einer lokalen Liste"
CONFIG=filter-big
EXPECT_CANARY=any
NOTE="Erzeugt im Gast eine Liste mit 5 Mio. Namen (Adblock-Format), startet den Dienst neu und misst WorkingSet/Peak von shuntd-win.exe. Danach muss ein Name aus der Liste NXDOMAIN bekommen und ein anderer nicht. Ziel: deutlich unter 1 GB."
PREP='
Add-Type -TypeDefinition "using System.IO; public static class G { public static void Run(string f,int n){ using(var w=new StreamWriter(f)){ for(int i=0;i<n;i++) w.WriteLine(\"||h\"+i.ToString(\"x\")+\".bigfilter.test^\"); } } }"
[G]::Run("C:\ProgramData\Shunt\big-filter.txt", 5000000)
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
$a = Nx "h4c4b3f.bigfilter.test"; "gelistet (Nr. 5000000-1 = h4c4b3f): $a"
if ($a -ne "NXDOMAIN") { "FAIL gelisteter Name nicht gesperrt" }
$b = Nx $c; "nicht gelistet: $b"
if ($p.PeakWorkingSet64 -gt 1GB) { "FAIL Peak ueber 1 GB" }
Get-Content C:\ProgramData\Shunt\shuntd.log -Tail 3
Remove-Item C:\ProgramData\Shunt\big-filter.txt -ErrorAction SilentlyContinue
'
