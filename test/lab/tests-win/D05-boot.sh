ID=D05
TITLE="Neustart: was geht raus, bevor der Dienst steht?"
EXPECT_CANARY=any
CHECKS=(discovery)
SETTLE=1
NOTE="Windows startet neu; das Gateway schneidet von vor dem Herunterfahren bis 60 s nach dem Start mit."
during() {
	# Restart-Computer fails in the VM after a few runs (RestartComputerFailed) and the test then
	# reported OK without a restart: shutdown.exe, and no restart is an error
	local before after
	before=$(client '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")' | tail -1)
	client 'shutdown /r /t 0 /f' || true
	sleep 40
	wait_for "client after reboot" 400 client 'exit 0'
	sleep 60
	after=$(client '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")' | tail -1)
	[[ -n $before && $before == "$after" ]] && echo "FAIL kein Neustart: LastBootUpTime unveraendert ($after)"
}
CLIENT='Start-Sleep 1'
