ID=WD05
TITLE="Nach hartem Aus der VM: Zustand beim Boot, Leck bis der Dienst steht?"
EXPECT_CANARY=any
SETTLE=1
source "$TESTS_DIR/_common.sh"
NOTE="Dienst laeuft, Probe-Aufgabe (SYSTEM, ab Boot), dann controlvm poweroff (hart), neu starten. Gateway schneidet vom Aus bis ~60 s nach Gast-Erreichbarkeit mit. Probe-Protokoll zeigt, ob vor dem Dienst etwas raus kam."
during() {
	sleep 4
	wd_install_probe "$canary"
	sleep 5
	echo "== hartes Aus $(date +%T)"
	VBoxManage controlvm "$CLIENT_VM" poweroff; sleep 6
	VBoxManage startvm "$CLIENT_VM" --type headless >/dev/null; echo "== Start $(date +%T)"
	wait_for "client after hard off" 700 client 'exit 0'
	echo "== Gast da $(date +%T)"
	sleep 60
	wd_read_boot
	client 'netsh wfp show filters file=C:\lab\wfp2.xml | Out-Null; "Quiet-Provider im XML: " + (Select-String -Path C:\lab\wfp2.xml -Pattern "The Shunt quiet mode" -SimpleMatch | Measure-Object).Count; "Quiet: Filter: " + (Select-String -Path C:\lab\wfp2.xml -Pattern "<name>Quiet:" | Measure-Object).Count'
}
CLIENT='Start-Sleep 1'
