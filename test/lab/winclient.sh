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

# Baseline for comparison (configs/win-wgplain.toml): the same tunnel as plain WireGuard for Windows (official client,
# tunnel service "labplain"), the Shunt service stopped and its firewall rules lifted. The MSI is WG_MSI (default
# $LAB_VPN_DIR/wireguard-amd64.msi, not in git); Windows itself checks its Authenticode signature (must be valid and
# from "WireGuard LLC") before it is installed. Config as most people write it: the lab's intern.conf (AllowedIPs
# 0.0.0.0/0, DNS 1.1.1.1); WireGuard for Windows adds its own firewall rules for a full tunnel.
WG_EXE='C:\Program Files\WireGuard\wireguard.exe'
win_plain_up() {
	local msi=${WG_MSI:-${LAB_VPN_DIR:-$HERE/vpn}/wireguard-amd64.msi}
	if [[ $(client "if (Test-Path '$WG_EXE') { 'yes' } else { 'no' }" | tail -1) != yes ]]; then
		[[ -f $msi ]] || { echo "no $msi (WireGuard for Windows MSI)" >&2; return 1; }
		client_cp_to "$msi" 'C:\lab\wg.msi' >/dev/null
		client '$s=Get-AuthenticodeSignature C:\lab\wg.msi; "sig: $($s.Status) $($s.SignerCertificate.Subject)"; if ($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "WireGuard LLC") { exit 3 }; Start-Process msiexec -ArgumentList "/i","C:\lab\wg.msi","/qn","/norestart" -Wait; Start-Sleep 5' || { echo "WireGuard MSI rejected or not installed" >&2; return 1; }
	fi
	client "Stop-Service Shunt -ErrorAction SilentlyContinue; & 'C:\Program Files\The Shunt\shuntd-win.exe' killswitch-off | Out-Null; & '$WG_EXE' /uninstalltunnelservice labplain 2>\$null; Start-Sleep 2; Copy-Item -Force C:\ProgramData\Shunt\tunnels\intern.conf C:\lab\labplain.conf; & '$WG_EXE' /installtunnelservice C:\lab\labplain.conf; for (\$i=0; \$i -lt 20; \$i++) { if ((Get-Service 'WireGuardTunnel\$labplain' -ErrorAction SilentlyContinue).Status -eq 'Running' -and (Get-NetAdapter labplain -ErrorAction SilentlyContinue).Status -eq 'Up') { break }; Start-Sleep 1 }; Start-Sleep 4; 'labplain: ' + (Get-NetAdapter labplain -ErrorAction SilentlyContinue).Status" | tail -1
}
win_plain_down() {
	client "& '$WG_EXE' /uninstalltunnelservice labplain 2>\$null; Remove-Item -Force C:\lab\labplain.conf -ErrorAction SilentlyContinue; Start-Service Shunt -ErrorAction SilentlyContinue; Start-Sleep 8"
}

apply_config() { # $1 = config name -> configs/win-<name>.toml; restarts the service only on change
	local f="$HERE/configs/win-$1.toml" want
	[[ -f $f ]] || { echo "no $f" >&2; return 1; }
	if [[ $(head -1 "$f") == "# baseline: wireguard-windows"* ]]; then
		[[ $(win_plain_up | tail -1) == "labplain: Up" ]] || { echo "plain WireGuard did not come up in the client" >&2; return 1; }
		return 0
	fi
	# coming back from the baseline: tunnel service off, Shunt service on
	if [[ $(client "if (Get-Service 'WireGuardTunnel\$labplain' -ErrorAction SilentlyContinue) { 'plain' } else { 'shunt' }" | tail -1) == plain ]]; then win_plain_down; fi
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
