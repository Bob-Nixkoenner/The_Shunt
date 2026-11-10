#!/usr/bin/env bash
# WD00: read Windows events in the desktop Windows lab VM (no snapshot restore, current state). Read only.
V=shunt-win11-lab; PW=$HOME/.shunt-foreign-win11-pw; OUT=$HOME/projects/shunt-lab-results/wd00; mkdir -p $OUT
PS='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
GC=(guestcontrol $V --username lab --passwordfile $PW)
echo "start $(date +%T)" > $OUT/status.log
VBoxManage startvm $V --type headless >>$OUT/status.log 2>&1
for i in $(seq 120); do
  VBoxManage "${GC[@]}" run --exe "$PS" --timeout 60000 -- -NoProfile -NonInteractive -Command 'hostname; (Get-Date).ToString("s")' >$OUT/hello.txt 2>/dev/null && break; sleep 10
done
echo "gast erreichbar nach $((i*10)) s $(date +%T)" >>$OUT/status.log; cat $OUT/hello.txt >>$OUT/status.log
cat >$OUT/wd00.ps1 <<'P'
$o='C:\lab\wd00.txt'; Remove-Item $o -ea 0
function W($t){ Add-Content $o $t }
W "== Systemzeit $(Get-Date -f s), letzter Start $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s'))"
W "== Schnellstart HiberbootEnabled: $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ea 0).HiberbootEnabled)"
$ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6005,6006,6008,7036,7043,41,109,1; StartTime=(Get-Date '2026-10-29')} -ea 0 | Sort-Object TimeCreated
W "== System-Ereignisse ab 29.10. ($($ev.Count))"
foreach($e in $ev){ $m=($e.Message -replace '\s+',' '); if($m.Length -gt 230){$m=$m.Substring(0,230)}; W ("{0} Id={1} {2} | {3}" -f $e.TimeCreated.ToString('s'),$e.Id,$e.ProviderName,$m) }
$wu = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; StartTime=(Get-Date '2026-10-29')} -ea 0 | Sort-Object TimeCreated
W "== WindowsUpdateClient ($($wu.Count))"
foreach($e in $wu){ $m=($e.Message -replace '\s+',' '); if($m.Length -gt 200){$m=$m.Substring(0,200)}; W ("{0} Id={1} | {2}" -f $e.TimeCreated.ToString('s'),$e.Id,$m) }
$sv = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034,7031,7023,7026; StartTime=(Get-Date '2026-10-29')} -ea 0 | Sort-Object TimeCreated
W "== Dienstfehler 7031/7034/7023/7026 ($($sv.Count))"
foreach($e in $sv){ $m=($e.Message -replace '\s+',' '); if($m.Length -gt 160){$m=$m.Substring(0,160)}; W ("{0} Id={1} | {2}" -f $e.TimeCreated.ToString('s'),$e.Id,$m) }
W "== Dienst Shunt: $((Get-Service Shunt -ea 0).Status)"
if(Test-Path 'C:\ProgramData\Shunt\shuntd.log'){ W "== shuntd.log (letzte 40 Zeilen)"; Get-Content 'C:\ProgramData\Shunt\shuntd.log' -Tail 40 | % { W $_ } }
P
VBoxManage "${GC[@]}" copyto $OUT/wd00.ps1 'C:\lab\wd00.ps1' >>$OUT/status.log 2>&1
VBoxManage "${GC[@]}" run --exe "$PS" --timeout 600000 -- -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\lab\wd00.ps1' >>$OUT/status.log 2>&1
VBoxManage "${GC[@]}" copyfrom 'C:\lab\wd00.txt' $OUT/wd00.txt >>$OUT/status.log 2>&1
echo "gelesen $(date +%T)" >>$OUT/status.log
# graceful shutdown, measure the time
t0=$(date +%s); VBoxManage "${GC[@]}" run --exe 'C:\Windows\System32\shutdown.exe' --timeout 30000 -- /s /t 5 >>$OUT/status.log 2>&1
for i in $(seq 120); do VBoxManage showvminfo $V --machinereadable | grep -q 'VMState="poweroff"' && break; sleep 5; done
echo "aus nach $(( $(date +%s)-t0 )) s (i=$i) $(date +%T)" >>$OUT/status.log
echo "fertig $(date +%T)" >>$OUT/status.log
