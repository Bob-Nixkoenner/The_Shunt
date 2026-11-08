#!/usr/bin/env bash
# WD02 matrix: Windows lab VM shutdown time, {Shunt service Running (lab net up) | StartPending (no gateway)} x {update services on | off}.
# Disk state continues from run to run (events of the previous shutdown are read at the next boot).
# R1 Running/updates on | R2 Running/updates off | R3 StartPending/updates off | R4 Running/updates restored
cd "$(dirname "$0")"
V=shunt-win11-lab; PW=$HOME/.shunt-foreign-win11-pw; OUT=$HOME/projects/shunt-lab-results/wd02; mkdir -p "$OUT"
export CLIENT_OS=windows CLIENT_VM=$V CLIENT_USER=lab PWFILE=$PW CT130_KEY=$HOME/.ssh/shunt-lab-ct130 KEY=$HOME/.ssh/shunt-vm LAB_OUT=$OUT
PS='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
GC=(guestcontrol $V --username lab --passwordfile $PW)
log() { echo "$(date +%T) $*" | tee -a "$OUT/status.log"; }
vm_off() { VBoxManage showvminfo $V --machinereadable | grep -q 'VMState="poweroff"'; }
ps_run() { local o rc; o=$(VBoxManage "${GC[@]}" run --exe "$PS" --timeout 300000 -- -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$1" 2>&1); rc=$?; printf '%s\n' "$o" | tr -d '\r'; return $rc; }
ps_file() { local t o rc; t=$(mktemp --suffix=.ps1); cat >"$t"; VBoxManage "${GC[@]}" copyto "$t" 'C:\lab\w.ps1' >/dev/null 2>&1; rm -f "$t"; o=$(VBoxManage "${GC[@]}" run --exe "$PS" --timeout 300000 -- -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\lab\w.ps1' 2>&1); rc=$?; printf '%s\n' "$o" | tr -d '\r'; return $rc; }
wait_guest() { for i in $(seq 120); do ps_run 'exit 0' >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
shutdown_timed() { # $1 = label
  local t0=$(date +%s) svc; svc=$(ps_run '(Get-Service Shunt).Status')
  log "$1: Shunt-Dienst vor dem Herunterfahren: $svc"
  VBoxManage "${GC[@]}" run --exe 'C:\Windows\System32\shutdown.exe' --timeout 30000 -- /s /t 5 >/dev/null 2>&1
  for i in $(seq 130); do vm_off && break; sleep 5; done
  if vm_off; then log "$1: aus nach $(( $(date +%s)-t0 )) s"; else log "$1: HAENGT (>650 s), harter Poweroff"; VBoxManage controlvm $V poweroff; sleep 5; fi
}
events() { # read the events of the last shutdown
  ps_file > "$OUT/events-$1.txt" <<'P'
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6006,6008,7043,41,109; StartTime=(Get-Date).AddHours(-3)} -ea 0 | Sort-Object TimeCreated | % { $m=($_.Message -replace '\s+',' '); if($m.Length -gt 170){$m=$m.Substring(0,170)}; '{0} Id={1} {2}' -f $_.TimeCreated.ToString('s'),$_.Id,$m }
P
log "Ereignisse $1: $(grep -c . "$OUT/events-$1.txt") Zeilen"
}
boot() { # $1 = label, $2 = lab|nolab
  vm_off || VBoxManage controlvm $V poweroff
  if [[ $2 == lab ]]; then bash lab.sh up >>"$OUT/up-$1.log" 2>&1; else bash lab.sh down >/dev/null 2>&1; VBoxManage modifyvm $V --nic1 intnet --intnet1 shuntlab; VBoxManage startvm $V --type headless >>"$OUT/up-$1.log" 2>&1; fi
  wait_guest || { log "$1: Gast nicht erreichbar"; return 1; }
  log "$1: Gast erreichbar ($2)"
}
log "=== WD02 Start"
# R1
boot R1 lab && { sleep 90; ps_run 'Get-Service Shunt,wuauserv,UsoSvc,BITS,DoSvc | % { "$($_.Name)=$($_.Status)/$($_.StartType)" }' > "$OUT/svc-R1.txt"; shutdown_timed "R1 Running/Updates an"; }
# R2: disable update services (remember originals)
boot R2 lab && { events R1; ps_file > "$OUT/svc-R2.txt" <<'P'
$n='DoSvc','wuauserv','UsoSvc','BITS'
$o=foreach($s in $n){ $k="HKLM:\SYSTEM\CurrentControlSet\Services\$s"; $p=Get-ItemProperty $k; [pscustomobject]@{Name=$s;Start=$p.Start;Delayed=$p.DelayedAutostart} }
$o | Export-Csv C:\lab\svc-orig.csv -NoTypeInformation; $o | % { "orig $($_.Name) Start=$($_.Start) Delayed=$($_.Delayed)" }
foreach($s in $n){ Stop-Service $s -Force -ea 0; & sc.exe config $s start= disabled | Out-Null; "$s -> $((Get-Service $s).Status)/$((Get-Service $s).StartType)" }
P
sleep 60; shutdown_timed "R2 Running/Updates aus"; }
# R3: no gateway -> Shunt service stays StartPending
boot R3 nolab && { events R2; sleep 45; ps_run '(Get-Service Shunt).Status; (Get-Service wuauserv).StartType' > "$OUT/svc-R3.txt"; shutdown_timed "R3 StartPending/Updates aus"; }
# R4: restore the service settings, Running again
boot R4 lab && { events R3; ps_file > "$OUT/svc-R4.txt" <<'P'
Import-Csv C:\lab\svc-orig.csv | % { $k="HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"; Set-ItemProperty $k -Name Start -Value ([int]$_.Start); if($_.Delayed -ne ''){ Set-ItemProperty $k -Name DelayedAutostart -Value ([int]$_.Delayed) -ea 0 }; "restored $($_.Name) Start=$($_.Start)" }
P
sleep 90; shutdown_timed "R4 Running/Updates wiederhergestellt"; }
vm_off || VBoxManage controlvm $V poweroff
bash lab.sh down >/dev/null 2>&1
log "=== WD02 fertig"
