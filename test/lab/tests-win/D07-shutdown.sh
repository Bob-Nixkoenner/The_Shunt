ID=D07
TITLE="Herunterfahren: nichts geht im Klartext raus, VM ist in 60 s aus"
EXPECT_CANARY=any
SETTLE=1
NOTE="Messschleife entkoppelt in der VM, dann shutdown /s /t 5. Gateway schneidet bis zum Ausschalten mit; danach startet die VM für den nächsten Test neu."
during() {
	sleep 3
	client 'shutdown /s /t 5' || true
	local t=0
	while [[ $(VBoxManage showvminfo "$CLIENT_VM" --machinereadable | grep ^VMState=) != *poweroff* ]] && ((t < 600)); do sleep 3; t=$((t + 3)); done
	echo "LABINFO aus nach ${t}s"
	((t < 60)) || echo "FAIL VM nach ${t}s nicht aus"
	VBoxManage startvm "$CLIENT_VM" --type headless
	wait_for "client after boot" 600 client 'exit 0'
}
CLIENT='
$loop = "1..400 | % { & C:\lab\labtun.exe -s -m1 -o NUL http://`$_-$c/; & C:\lab\labfree.exe -s -m1 -o NUL http://1.1.1.1/; Start-Sleep -Milliseconds 500 }"
([wmiclass]"Win32_Process").Create("powershell -NoProfile -Command $loop") | Out-Null
Start-Sleep 2
'
