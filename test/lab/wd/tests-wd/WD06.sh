ID=WD06
TITLE="Schnellstart (HiberbootEnabled=${WD_FASTBOOT:-1}): herunterfahren, kalt starten, Kill-Switch ab Sekunde 1?"
EXPECT_CANARY=any
SETTLE=1
source "$TESTS_DIR/_common.sh"
NOTE="HiberbootEnabled=${WD_FASTBOOT:-1}, Probe-Aufgabe ab Boot, shutdown /s /t 5, VM aus abwarten, kalt starten (startvm). Gateway schneidet durchgehend mit."
during() {
	sleep 4
	client "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' HiberbootEnabled ${WD_FASTBOOT:-1}; powercfg /h on 2>&1 | Out-Null; 'HiberbootEnabled=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled; (powercfg /a) -join ' ' | Select-String 'Ruhezustand|Hibernate|Schnellstart' | Select -First 1"
	wd_install_probe "$canary"
	sleep 3
	echo "== shutdown $(date +%T)"
	local t0=$(date +%s)
	client 'shutdown /s /t 5' || true
	for i in $(seq 100); do [[ $(vm_state "$CLIENT_VM") == poweroff ]] && break; sleep 3; done
	if [[ $(vm_state "$CLIENT_VM") == poweroff ]]; then echo "VM aus nach $(( $(date +%s)-t0 )) s"; else echo "FAIL VM nach 300 s nicht aus (haengt), harter Poweroff"; VBoxManage controlvm "$CLIENT_VM" poweroff; sleep 5; fi
	sleep 5
	VBoxManage startvm "$CLIENT_VM" --type headless >/dev/null; echo "== Kaltstart $(date +%T)"
	wait_for "client after cold start" 700 client 'exit 0'
	echo "== Gast da $(date +%T)"
	sleep 60
	wd_read_boot
}
CLIENT='Start-Sleep 1'
