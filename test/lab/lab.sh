#!/usr/bin/env bash
# Shunt test lab: a client VM behind a gateway VM we control ("the café Wi-Fi"),
# with captures at three points:
#
#   [client VM] ──intnet shuntlab──► [shunt-lab-gw] ──NAT──► … ──► [CT130 tunnel exit]
#    1: bpftrace                      2: tcpdump/unbound/dnsmasq   3: tcpdump on wgt0
#
#   lab.sh gw-create            clone shunt-lab-gw from the client's "sauber" snapshot
#   lab.sh gw-setup             (re)install gw/ on the gateway
#   lab.sh up [snapshot]        start both VMs, client on the lab LAN (restores snapshot)
#   lab.sh down                 power both off
#   lab.sh detach               client back to plain VirtualBox NAT (ssh :2224)
#   lab.sh client-prep <deb>    install Shunt + lab tools in the client, snapshot "lab-basis"
#   lab.sh mode <m> | netem … | status    passed to labctl on the gateway
#   lab.sh ssh <cmd>            command in the client (guest control, no network)
#   lab.sh gw [cmd]             shell/command on the gateway (root)
#   lab.sh run [test…]          run tests (files in tests/, IDs like A01; none = all)
#   lab.sh scan <id>            port scan of the client from the gateway
#
# CLIENT_OS=windows lab.sh …   same with the Windows client VM (tests-win/*.ps1)
#
# Results go to $LAB_OUT (default ~/projects/shunt-lab-results), never into
# the repo or Nextcloud: pcaps may contain clear text.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# machine-specific settings (user names, addresses of your own servers): not in git
# shellcheck source=/dev/null
[[ -f $HERE/local.env ]] && source "$HERE/local.env"
GW_VM=${GW_VM:-shunt-lab-gw}
# CLIENT_OS=windows: client is the Windows VM, driven by PowerShell (winclient.sh, tests-win/)
if [[ ${CLIENT_OS:-linux} == windows ]]; then
	CLIENT_VM=${CLIENT_VM:-shunt-win11-lab}
	TUNNEL_IP=${TUNNEL_IP:-10.66.0.15}
	CLIENT_IF=${CLIENT_IF:-Ethernet}
	CLIENT_PING='exit 0'
	CLIENT_BOOT=600
	TESTS_DIR=${TESTS_DIR:-$(cd "$(dirname "$0")" && pwd)/tests-win}
	TEST_EXT=sh
	export TUNNEL_IP CLIENT_IF TESTS_DIR TEST_EXT
fi
CLIENT_VM=${CLIENT_VM:-shunt-ubuntu}
# virtio gives the guest a real driver (F05: changing the MAC works); Windows has none -> default e1000
[[ ${CLIENT_OS:-linux} == windows ]] || CLIENT_NIC=${CLIENT_NIC:-virtio}
GW_PORT=${GW_PORT:-2225}
KEY=${KEY:-$HOME/.ssh/shunt-vm}
USER_VM=${USER_VM:?set USER_VM in local.env (the account in the lab VMs)}
CT130=${CT130:?set CT130 in local.env (ssh target of the tunnel test server)}
CT130_IF=${CT130_IF:-wgt0}
LAB_OUT=${LAB_OUT:-$HOME/projects/shunt-lab-results}
# WireGuard config of the client's tunnel "intern" (test keys, not in git)
TUNNEL_CONF=${TUNNEL_CONF:-$HOME/Nextcloud/Shared/PC/Linux/the-shunt/vm-dateien/testserver-intern/wg-intern-linux-test.conf}
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o LogLevel=ERROR -o ConnectTimeout=8 -o ServerAliveInterval=10)

gw() { ssh "${SSHO[@]}" -p "$GW_PORT" "$USER_VM@127.0.0.1" "sudo $(printf '%q ' "$@")"; }
gw_cp_from() { scp "${SSHO[@]}" -P "$GW_PORT" -r "$USER_VM@127.0.0.1:$1" "$2"; }
gw_cp_to() { scp "${SSHO[@]}" -P "$GW_PORT" -r "$1" "$USER_VM@127.0.0.1:$2"; }
client_ip() { gw labctl client | awk '{print $2}'; }
# The client is driven through VirtualBox guest control, never over the
# network: no management traffic in the captures, and Shunt cannot cut us off.
# CLIENT_USER: the guest account if it differs from the gateway user (Kali: kali)
GC=(guestcontrol "$CLIENT_VM" --username "${CLIENT_USER:-$USER_VM}" --passwordfile "${PWFILE:-$HOME/.shunt-ubuntu-pw}")
client() { # command line, run by bash as $USER_VM (sudo -n works)
	# guest control starts without a login shell: /usr/local/bin (the lab apps) may be missing (CachyOS)
	VBoxManage "${GC[@]}" run --exe /bin/bash --timeout "${CLIENT_TIMEOUT:-600000}" -- -c "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; $*"
}
client_script() { # stdin = script, args = its arguments
	local f=/tmp/shuntlab-$$.sh tmp
	tmp=$(mktemp)
	cat >"$tmp"
	VBoxManage "${GC[@]}" copyto "$tmp" "$f" && rm -f "$tmp"
	client "bash $f $(printf '%q ' "$@"); rc=\$?; rm -f $f; exit \$rc"
}
client_cp_to() { # files… dir
	local dir=${*: -1}
	client "mkdir -p $dir"
	VBoxManage "${GC[@]}" copyto --target-directory "$dir" "${@:1:$#-1}"
}
client_cp_from() { VBoxManage "${GC[@]}" copyfrom "$1" "$2"; }
# CT130_KEY: a key that CT130 only lets run the capture commands (gw/ct130-capture)
ct130() { ssh ${CT130_KEY:+-i "$CT130_KEY" -o IdentitiesOnly=yes} -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$CT130" "$@"; }
vm_state() { VBoxManage showvminfo "$1" --machinereadable | sed -n 's/^VMState="\(.*\)"/\1/p'; }
poweroff() { [[ $(vm_state "$1") == running ]] && VBoxManage controlvm "$1" poweroff >/dev/null 2>&1; sleep 2; return 0; }

wait_for() { # $1 = what, $2 = seconds, rest = command
	local what=$1 t=$2
	shift 2
	for ((i = 0; i < t; i += 3)); do
		"$@" >/dev/null 2>&1 && return 0
		sleep 3
	done
	echo "timeout waiting for $what" >&2
	return 1
}

gw_up() {
	[[ $(vm_state "$GW_VM") == running ]] || VBoxManage startvm "$GW_VM" --type headless >/dev/null
	wait_for gateway 180 gw true
}

client_to_lab() {
	VBoxManage modifyvm "$CLIENT_VM" --nic1 intnet --intnet1 shuntlab --nicpromisc1 allow-all ${CLIENT_NIC:+--nictype1 $CLIENT_NIC} --memory "${CLIENT_MEM:-3072}"
}

cmd_up() { # [snapshot]
	gw_up
	poweroff "$CLIENT_VM"
	[[ -n ${1:-} ]] && VBoxManage snapshot "$CLIENT_VM" restore "$1" >/dev/null
	# a saved state cannot change NICs: snapshots taken live come back saved
	[[ $(vm_state "$CLIENT_VM") == saved ]] && VBoxManage discardstate "$CLIENT_VM"
	client_to_lab
	VBoxManage startvm "$CLIENT_VM" --type headless >/dev/null
	wait_for "client guest control" "${CLIENT_BOOT:-300}" client "${CLIENT_PING:-true}"
	wait_for "client lease" 120 gw labctl client
	echo "client $(gw labctl client)"
}

case ${1:-} in
gw-create)
	VBoxManage clonevm "$CLIENT_VM" --snapshot sauber --options link --name "$GW_VM" --register
	VBoxManage modifyvm "$GW_VM" --memory 1024 --cpus 2 --nic1 nat --nic2 intnet --intnet2 shuntlab \
		--nicpromisc2 allow-all --audio-enabled off
	VBoxManage modifyvm "$GW_VM" --natpf1 delete ssh 2>/dev/null || true
	VBoxManage modifyvm "$GW_VM" --natpf1 "ssh,tcp,127.0.0.1,$GW_PORT,,22"
	echo "start it, copy the ssh key (ssh-copy-id -p $GW_PORT), then: lab.sh gw-setup" ;;
gw-setup)
	gw_up
	gw rm -rf /tmp/shuntlab-gw
	gw_cp_to "$HERE/gw" /tmp/shuntlab-gw
	gw_cp_to "$HERE/analyze.py" /tmp/shuntlab-gw/
	gw bash /tmp/shuntlab-gw/setup.sh
	# tunnel endpoints for the tunnelkill mode (ip:port/proto, space separated)
	[[ -z ${LAB_ENDPOINTS:-} ]] || gw bash -c "printf '%s\\n' $LAB_ENDPOINTS >/etc/shuntlab/endpoints"
	gw install -m 755 /tmp/shuntlab-gw/analyze.py /usr/local/lib/analyze.py
	gw sync ;; # "down" powers off hard: unsynced files come back empty
up) cmd_up "${2:-}" ;;
down) poweroff "$CLIENT_VM"; poweroff "$GW_VM" ;;
detach)
	poweroff "$CLIENT_VM"
	VBoxManage modifyvm "$CLIENT_VM" --nic1 nat
	VBoxManage modifyvm "$CLIENT_VM" --natpf1 delete ssh 2>/dev/null || true
	VBoxManage modifyvm "$CLIENT_VM" --natpf1 "ssh,tcp,127.0.0.1,2224,,22"
	echo "client on NAT again (ssh -p 2224)" ;;
client-prep)
	deb=${2:?the-shunt_*.deb}
	client_cp_to "$deb" "$HERE/client/"* "$HERE/configs/base.toml" /tmp/shuntlab
	VBoxManage "${GC[@]}" copyto "$TUNNEL_CONF" /tmp/shuntlab/intern.conf
	client "sudo -n bash /tmp/shuntlab/prep.sh /tmp/shuntlab/$(basename "$deb")"
	client 'sudo -n poweroff' || true
	wait_for "client poweroff" 120 bash -c "[[ \$(VBoxManage showvminfo $CLIENT_VM --machinereadable | grep ^VMState=) == *poweroff* ]]"
	VBoxManage snapshot "$CLIENT_VM" take lab-basis --description "lab client: Shunt $(basename "$deb"), bpftrace, lab apps" >/dev/null
	echo "snapshot lab-basis taken" ;;
mode | netem | status) gw labctl "$@" ;;
ssh) shift; client "${*:-bash -l}" ;;
gw) shift; if (($#)); then gw "$@"; else ssh -t "${SSHO[@]}" -p "$GW_PORT" "$USER_VM@127.0.0.1"; fi ;;
scan)
	id=${2:?id}
	gw labctl scan "$id" ;;
run)
	shift
	# shellcheck source=run-test.sh
	source "$HERE/run-test.sh"
	(($#)) || set -- "${TESTS_DIR:-$HERE/tests}"/*."${TEST_EXT:-sh}"
	for t in "$@"; do run_test "$t" || FOUND+=("$t(error)"); done
	summary ;;
*) sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 1 ;;
esac
