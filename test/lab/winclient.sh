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

# Multi-hop (configs/win-hop.toml): the inner WireGuard hop needs tunnels\hop.conf in the client.
# WIN_HOP_CONF = the Windows VM's hop file (test keys, not in git); HOP_BADKEY=1 (test file) writes
# it with a wrong server key (MH03). Copied only when it differs; a change restarts the service below.
# (resolved when used: lab.sh sources this file before run-test.sh sets HOP_DIR)
win_ensure_hop() {
	local tmp want conf=${WIN_HOP_CONF:-$HOP_DIR/wg-hop-lab-win.conf}
	tmp=$(mktemp)
	cp "$conf" "$tmp" || { rm -f "$tmp"; echo "no $conf" >&2; return 1; }
	[[ ${HOP_BADKEY:-0} == 1 ]] && sed -i "s|^PublicKey *=.*|PublicKey = $(head -c32 /dev/urandom | base64)|" "$tmp"
	want=$(sha256sum <"$tmp" | cut -c1-16)
	if [[ $(client '$f="C:\ProgramData\Shunt\tunnels\hop.conf"; if (Test-Path $f) { (Get-FileHash $f -Algorithm SHA256).Hash.Substring(0,16).ToLower() }') != "$want" ]]; then
		VBoxManage "${GC[@]}" copyto "$tmp" 'C:\lab\hop.conf' >/dev/null
		# Copy, not Move: the copy takes the admin-only rights of tunnels\ (a moved file keeps those of C:\lab)
		client 'Copy-Item -Force C:\lab\hop.conf C:\ProgramData\Shunt\tunnels\hop.conf; Remove-Item C:\lab\hop.conf; Restart-Service Shunt -WarningAction SilentlyContinue; Start-Sleep 8'
	fi
	rm -f "$tmp"
}

apply_config() { # $1 = config name -> configs/win-<name>.toml; restarts the service only on change
	local f="$HERE/configs/win-$1.toml" want
	[[ -f $f ]] || { echo "no $f" >&2; return 1; }
	if grep -q 'tunnels/hop\.conf' "$f"; then win_ensure_hop || return 1; fi
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
