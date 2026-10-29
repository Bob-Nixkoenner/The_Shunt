# Windows client for the lab (CLIENT_OS=windows). Sourced by run-test.sh, replaces
# the Linux client hooks. The VM is driven by guest control + PowerShell only, like
# the Linux client (no management traffic on the lab LAN). No process trace
# (no bpftrace): findings come from the gateway/CT130 captures and the checks in
# the test script ("FAIL ..." lines).
#
# Client layout: C:\lab\labtun.exe, labdir.exe, labfree.exe (copies of curl.exe),
# C:\ProgramData\Shunt\shunt.toml from configs/win-<config>.toml, service "Shunt".
PS='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
GC=(guestcontrol "$CLIENT_VM" --username "${CLIENT_USER:-shunt}" --passwordfile "${PWFILE:-$HOME/.shunt-win11-pw}")

client() { # PowerShell command line
	VBoxManage "${GC[@]}" run --exe "$PS" --timeout "${CLIENT_TIMEOUT:-600000}" -- -NoProfile -NonInteractive -Command "$*" | tr -d '\r'
	return "${PIPESTATUS[0]}"
}
client_script() { # stdin = PowerShell script, args = its arguments ($args[0] = canary)
	local tmp
	tmp=$(mktemp --suffix=.ps1)
	{ printf '%s\n' "\$ErrorActionPreference='Continue'; \$c=\$args[0]"; cat; } >"$tmp"
	VBoxManage "${GC[@]}" copyto "$tmp" 'C:\lab\t.ps1' >/dev/null && rm -f "$tmp"
	VBoxManage "${GC[@]}" run --exe "$PS" --timeout "${CLIENT_TIMEOUT:-600000}" -- -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\lab\t.ps1' "$@" | tr -d '\r'
	return "${PIPESTATUS[0]}"
}
client_cp_to() { VBoxManage "${GC[@]}" copyto --target-directory "${@: -1}" "${@:1:$#-1}"; }
client_cp_from() { VBoxManage "${GC[@]}" copyfrom "$1" "$2"; }

apply_config() { # $1 = config name -> configs/win-<name>.toml; restarts the service only on change
	local f="$HERE/configs/win-$1.toml" want
	[[ -f $f ]] || { echo "no $f" >&2; return 1; }
	want=$(sha256sum <"$f" | cut -c1-16)
	if [[ $(client '(Get-FileHash C:\ProgramData\Shunt\shunt.toml -Algorithm SHA256).Hash.Substring(0,16).ToLower()') != "$want" ]]; then
		VBoxManage "${GC[@]}" copyto "$f" 'C:\ProgramData\Shunt\shunt.toml' >/dev/null
		client 'Restart-Service Shunt -WarningAction SilentlyContinue; Start-Sleep 8'
	fi
}
# release first: Windows keeps DHCP option-121 routes (TunnelVision, E01) across a plain /renew;
# left-over /1 routes on the LAN beat a tunnel 0.0.0.0/0 and make every later test invalid
renew_client() {
	client 'ipconfig /release Ethernet | Out-Null; Get-NetRoute -AddressFamily IPv4 -InterfaceAlias Ethernet -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in "0.0.0.0/1","128.0.0.0/1" } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; ipconfig /renew Ethernet | Out-Null'
	sleep 4
}

client_trace() { :; } # no process trace on Windows (see above)
client_version() { client '(Get-Item "C:\Program Files\The Shunt\shuntd-win.exe").VersionInfo.ProductVersion; ' | tail -1; }
