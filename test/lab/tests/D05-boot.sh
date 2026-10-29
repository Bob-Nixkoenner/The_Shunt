ID=D05
TITLE="Neustart: was geht raus, bevor shuntd steht?"
EXPECT_CANARY=any
SETTLE=1
NOTE="Der Client startet neu; das Gateway schneidet von vor dem Herunterfahren bis 60 s nach dem Start mit. Ohne bpftrace (Neustart)."
during() {
	client 'sudo -n systemctl reboot' || true
	sleep 25
	wait_for "client after reboot" 300 client true
	sleep 60
	client "sudo -n /usr/local/lib/shuntlab/trace.sh start /tmp/shuntlab-trace.log" # so stop/copy find a file
}
CLIENT='true'
