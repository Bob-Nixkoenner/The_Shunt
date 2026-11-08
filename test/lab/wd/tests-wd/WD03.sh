ID=WD03
TITLE="Stop-Service Shunt 10x: Kill-Switch/WFP-Sperre bleibt, kein Leck, Stoppzeit"
EXPECT_CANARY=any
SETTLE=1
WD_N=${WD_N:-10}
NOTE="Je Durchlauf: Dienst laeuft, Stop-Service (gemessen), danach Tunnel-App/App ohne Regel nach 1.1.1.1 (darf nicht raus), WFP-Filterzahl vorher/nachher, Start-Service. Entkoppelte Schleife sendet die ganze Zeit Anfragen (Canary), das Gateway schneidet mit. WD_N=$WD_N"
CLIENT='
$ErrorActionPreference="Continue"
New-Item -ItemType Directory C:\lab -Force | Out-Null
Remove-Item C:\lab\wd03-stop,C:\lab\wd03-probe.log -ErrorAction SilentlyContinue
$sb = {
$i=0; while (-not (Test-Path C:\lab\wd03-stop) -and $i -lt 2000) { $i++
  & C:\lab\labfree.exe -s -m1 -o NUL "http://w$i-$c/" 2>$null
  Resolve-DnsName "w$i-$c" -Server 10.77.0.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep -Milliseconds 300 }
}
Set-Content C:\lab\wd03-probe.ps1 ("`$c=`"$c`"`r`n" + $sb.ToString())
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\wd03-probe.ps1"} | Out-Null
function Wfp { netsh wfp show filters file=C:\lab\wfp.xml | Out-Null; (Select-String -Path C:\lab\wfp.xml -Pattern "Shunt" -SimpleMatch | Measure-Object).Count }
function WaitRun($s) { $t=Get-Date; while ((Get-Service Shunt).Status -ne "Running" -and ((Get-Date)-$t).TotalSeconds -lt $s) { Start-Sleep 1 }; return [math]::Round(((Get-Date)-$t).TotalSeconds,1) }
$null = WaitRun 90; Start-Sleep 5
"Version: " + (Get-Item "C:\Program Files\The Shunt\shuntd-win.exe").VersionInfo.ProductVersion
"Config: " + ((Get-Content C:\ProgramData\Shunt\shunt.toml | Select-String "default_route|driver|kill_switch") -join " ; ")
"# i | stop_s | wfp_vor | wfp_nach | tunapp_exit | freeapp_exit | start_bis_Running_s | shuntd/tor Prozesse nach Stop"
for ($n=1; $n -le '$WD_N'; $n++) {
  if ((Get-Service Shunt).Status -ne "Running") { Start-Service Shunt -ErrorAction SilentlyContinue; $null = WaitRun 90 }
  Start-Sleep 6
  $w0 = Wfp
  $ts = [math]::Round((Measure-Command { Stop-Service Shunt -WarningAction SilentlyContinue }).TotalSeconds,1)
  Start-Sleep 1
  $w1 = Wfp
  & C:\lab\labtun.exe -s -m3 -o NUL http://1.1.1.1/; $e1=$LASTEXITCODE
  & C:\lab\labfree.exe -s -m3 -o NUL http://1.1.1.1/; $e2=$LASTEXITCODE
  $pr = (Get-Process shuntd-win,tor -ErrorAction SilentlyContinue | Measure-Object).Count
  $st = (Get-Service Shunt).Status
  $t0=Get-Date; Start-Service Shunt -ErrorAction SilentlyContinue; $rs = WaitRun 90
  "$n | $ts | $w0 | $w1 | $e1 | $e2 | $rs | $pr | nach Stop: $st"
  if ($ts -gt 20) { "FAIL Lauf $n : Stop-Service dauerte $ts s (>20 s)" }
  if ($w1 -lt $w0 -or $w1 -eq 0) { "FAIL Lauf $n : WFP-Filter nach Stop weniger ($w0 -> $w1)" }
  if ($e1 -eq 0) { "FAIL Lauf $n : Tunnel-App kam ohne Dienst nach 1.1.1.1 raus" }
  if ($e2 -eq 0) { "FAIL Lauf $n : App ohne Regel kam ohne Dienst nach 1.1.1.1 raus" }
  if ($st -ne "Stopped") { "FAIL Lauf $n : Dienststatus nach Stop: $st" }
}
New-Item C:\lab\wd03-stop -ItemType File -Force | Out-Null
"== Ereignisse 7031/7034/7023/7043 (Shunt), 7036 Zahl:"
Get-WinEvent -FilterHashtable @{LogName="System"; Id=7031,7034,7023,7043; StartTime=(Get-Date).AddHours(-1)} -ea 0 | ? { $_.Message -match "Shunt" } | % { "$($_.TimeCreated.ToString("s")) Id=$($_.Id) $(($_.Message -replace "\s+"," ").Substring(0,[math]::Min(160,$_.Message.Length)))" }
"== shuntd.log Ende:"
Get-ChildItem C:\ProgramData\Shunt\*.log | Sort LastWriteTime | Select -Last 1 | % { Get-Content $_.FullName -Tail 15 }
'
