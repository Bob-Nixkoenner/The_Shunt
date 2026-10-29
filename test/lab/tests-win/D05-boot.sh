ID=D05
TITLE="Neustart: was geht raus, bevor der Dienst steht?"
EXPECT_CANARY=any
SETTLE=1
NOTE="Windows startet neu; das Gateway schneidet von vor dem Herunterfahren bis 60 s nach dem Start mit."
during() {
	client 'Restart-Computer -Force' || true
	sleep 40
	wait_for "client after reboot" 400 client 'exit 0'
	sleep 60
}
CLIENT='Start-Sleep 1'
