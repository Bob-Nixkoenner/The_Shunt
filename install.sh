#!/usr/bin/env bash
# The Shunt installer for Debian-based systems (Pop!_OS, Ubuntu, Debian, Kali).
#
#   curl -fsSLo install.sh https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/main/install.sh
#   less install.sh          # read before you run things as root
#   sudo bash install.sh
#
# Options / environment:
#   --uninstall [--purge]   remove Shunt (--purge also deletes /etc/shunt)
#   --from-source           build from git even if a release exists
#   SHUNT_REF=<branch|tag>  git ref for source builds (default: the repo's default branch)
#   SHUNT_WG_CONF=<file>    WireGuard config to import without asking
#   SHUNT_YES=1             answer every question with the default
set -euo pipefail

REPO=Bob-Nixkoenner/The_Shunt
REF=${SHUNT_REF:-HEAD}   # HEAD = default branch (works for raw URLs too)
BIN_DIR=/usr/local/bin
ETC=/etc/shunt
UNIT=/etc/systemd/system/shuntd.service
LOCKDOWN_UNIT=/etc/systemd/system/shunt-lockdown.service

# ---------------------------------------------------------------- helpers
c_red=$'\e[31m' c_grn=$'\e[32m' c_yel=$'\e[33m' c_bld=$'\e[1m' c_off=$'\e[0m'
[[ -t 1 ]] || { c_red='' c_grn='' c_yel='' c_bld='' c_off=''; }
say() { printf '%s==>%s %s\n' "$c_bld" "$c_off" "$*"; }
ok() { printf '  %s✔%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '  %s!%s %s\n' "$c_yel" "$c_off" "$*"; }
die() {
	printf '%sERROR:%s %s\n' "$c_red" "$c_off" "$*" >&2
	exit 1
}

# Questions go to the terminal even when the script itself is piped in.
TTY=/dev/tty
[[ -r $TTY && -z ${SHUNT_YES:-} ]] || TTY=
ask() { # ask "question" default -> echoes answer
	local q=$1 def=${2:-} a=
	if [[ -n $TTY ]]; then
		printf '  %s?%s %s [%s] ' "$c_bld" "$c_off" "$q" "$def" >"$TTY"
		read -r a <"$TTY" || true
	fi
	echo "${a:-$def}"
}
yes_no() { [[ $(ask "$1 (y/n)" "${2:-y}") =~ ^[yYjJ] ]]; }

# Long steps run in the background with a spinner and elapsed time; their
# output goes to a log that is shown when they fail.
LOG=/var/log/shunt-install.log
step() { # step "message" cmd...
	local msg=$1 pid rc i=0 t0=$SECONDS spin='|/-\'
	shift
	echo "--- $msg: $*" >>"$LOG"
	"$@" >>"$LOG" 2>&1 &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		if [[ -t 1 ]]; then
			local extra=''
			if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && ! pgrep -P "$pid" -f 'apt|dpkg' >/dev/null && [[ $msg == *apt* || $msg == *packages* ]]; then
				extra=' (waiting for another package manager to finish)'
			fi
			printf '\r  %s %s ... %ds%s ' "${spin:i++%4:1}" "$msg" $((SECONDS - t0)) "$extra"
		fi
		sleep 0.2
	done
	wait "$pid" && rc=0 || rc=$?
	[[ -t 1 ]] && printf '\r\033[K'
	if ((rc)); then
		printf '  %s✘%s %s failed (exit %d). Last lines of %s:\n' "$c_red" "$c_off" "$msg" "$rc" "$LOG"
		tail -n 25 "$LOG" | sed 's/^/    /'
		exit "$rc"
	fi
	ok "$msg ($((SECONDS - t0))s)"
}
APT=(apt-get -o DPkg::Lock::Timeout=600 -y -q)

SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)
MODE=install FROM_SOURCE=0 PURGE=0
for a in "$@"; do
	case $a in
	--uninstall) MODE=uninstall ;;
	--purge) PURGE=1 ;;
	--from-source) FROM_SOURCE=1 ;;
	-h | --help)
		sed -n '2,15p' "$0"
		exit 0
		;;
	*) die "unknown option $a" ;;
	esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"

# ---------------------------------------------------------------- uninstall
if [[ $MODE == uninstall ]]; then
	say "Removing The Shunt"
	systemctl disable --now shuntd.service shunt-lockdown.service 2>/dev/null || true
	if [[ -x $BIN_DIR/shuntd ]]; then
		"$BIN_DIR/shuntd" cleanup && ok "rules, routes and kill switches removed"
		[[ -f /etc/nsswitch.conf.shunt-backup ]] && "$BIN_DIR/shuntd" restore-nsswitch && ok "nsswitch.conf restored"
	fi
	rm -f "$UNIT" "$LOCKDOWN_UNIT" "$BIN_DIR/shuntd" "$BIN_DIR/shunt"
	[[ -L /usr/sbin/shuntd ]] && rm -f /usr/sbin/shuntd
	systemctl daemon-reload
	if ((PURGE)); then
		rm -rf "$ETC" && ok "removed $ETC (including your tunnel keys)"
	else
		ok "kept $ETC (use --purge to delete it)"
	fi
	ok "done. Your network is back to normal."
	exit 0
fi

# ---------------------------------------------------------------- checks
say "Checking the system"
[[ $(uname -s) == Linux ]] || die "Linux only"
[[ -d /run/systemd/system ]] || die "systemd is required"
command -v apt-get >/dev/null || die "only Debian-based systems (apt) are supported by this installer"
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] ||
	die "cgroup v2 (unified hierarchy) is required; boot with systemd.unified_cgroup_hierarchy=1"
IFS=. read -r kmaj kmin _ <<<"$(uname -r)"
((kmaj > 5 || (kmaj == 5 && kmin >= 13))) || die "kernel 5.13 or newer needed (have $(uname -r))"
case $(uname -m) in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) die "unsupported CPU $(uname -m)" ;;
esac
ok "Linux $(uname -r), systemd, cgroup v2, $ARCH"
if modprobe -n wireguard 2>/dev/null; then
	ok "kernel WireGuard available"
else
	warn "no WireGuard kernel module: Shunt will use its built-in wireguard-go (slower, works)"
fi

say "Installing dependencies"
: >"$LOG"
export DEBIAN_FRONTEND=noninteractive
step "updating package lists (apt)" "${APT[@]}" update
step "installing nftables, wireguard-tools (apt)" "${APT[@]}" install nftables wireguard-tools curl ca-certificates psmisc

# ---------------------------------------------------------------- binaries
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

build_from() { # source dir
	if ! command -v go >/dev/null || ! command -v git >/dev/null; then
		step "installing Go and git (apt)" "${APT[@]}" install golang-go git
	fi
	local gov
	gov=$(go env GOVERSION | sed 's/^go//')
	IFS=. read -r gmaj gmin _ <<<"$gov"
	((gmaj > 1 || gmin >= 21)) || die "Go $gov is too old to fetch the required toolchain; install Go >= 1.21"
	say "Building from source"
	local ver
	ver=src-$(git -C "$1" rev-parse --short HEAD 2>/dev/null || echo local)
	step "downloading Go toolchain and modules" env -C "$1" GOCACHE="$WORK/cache" GOMODCACHE="$WORK/mod" go mod download
	step "compiling shuntd and shunt" env -C "$1" GOFLAGS=-trimpath GOCACHE="$WORK/cache" GOMODCACHE="$WORK/mod" CGO_ENABLED=0 \
		go build -ldflags "-s -w -X main.version=$ver" -o "$WORK/bin/" ./cmd/shuntd ./cmd/shunt
}

if [[ -f $SRC_DIR/go.mod && -d $SRC_DIR/cmd/shuntd ]]; then
	build_from "$SRC_DIR"
else
	tag=
	if ((!FROM_SOURCE)); then
		tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null |
			sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1) || true
	fi
	if [[ -n $tag ]]; then
		say "Downloading release $tag"
		base=https://github.com/$REPO/releases/download/$tag
		curl -fsSLo "$WORK/shunt.tar.gz" "$base/shunt_linux_$ARCH.tar.gz"
		curl -fsSLo "$WORK/SHA256SUMS" "$base/SHA256SUMS"
		(cd "$WORK" && grep " shunt_linux_$ARCH.tar.gz\$" SHA256SUMS | sed "s/shunt_linux_$ARCH.tar.gz/shunt.tar.gz/" | sha256sum -c --quiet) ||
			die "checksum mismatch - download corrupted or tampered with"
		mkdir -p "$WORK/bin" && tar -xzf "$WORK/shunt.tar.gz" -C "$WORK/bin"
		ok "checksum verified"
	else
		command -v git >/dev/null || step "installing git (apt)" "${APT[@]}" install git
		say "No release yet, building from source ($REF)"
		branch_opt=()
		[[ $REF == HEAD ]] || branch_opt=(--branch "$REF")
		step "downloading source" git clone -q --depth 1 "${branch_opt[@]}" "https://github.com/$REPO" "$WORK/src"
		build_from "$WORK/src"
		SRC_DIR=$WORK/src
	fi
fi
install -m755 "$WORK/bin/shuntd" "$WORK/bin/shunt" "$BIN_DIR/"
# sudo's secure_path does not include /usr/local/bin everywhere (Kali)
ln -sf "$BIN_DIR/shuntd" /usr/sbin/shuntd
ok "installed $("$BIN_DIR/shuntd" version) to $BIN_DIR"

unit_src() { # file name -> path of packaged unit (or download)
	if [[ -f $SRC_DIR/packaging/systemd/$1 ]]; then
		echo "$SRC_DIR/packaging/systemd/$1"
	else
		curl -fsSLo "$WORK/$1" "https://raw.githubusercontent.com/$REPO/$REF/packaging/systemd/$1"
		echo "$WORK/$1"
	fi
}

# ---------------------------------------------------------------- config
say "Configuration"
getent group shunt >/dev/null || groupadd --system shunt
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
	usermod -aG shunt "$SUDO_USER"
	ok "user $SUDO_USER may use the 'shunt' command (after logging in again)"
fi
install -d -m755 "$ETC"
install -d -m700 "$ETC/tunnels"

if [[ -f $ETC/shunt.toml ]]; then
	ok "keeping existing $ETC/shunt.toml"
else
	wg=${SHUNT_WG_CONF:-}
	if [[ -z $wg ]]; then
		found=$(ls /etc/wireguard/*.conf 2>/dev/null | head -1 || true)
		wg=$(ask "WireGuard config to import (empty = none for now)" "$found")
	fi
	tunnel_block='' rule_hint=''
	if [[ -n $wg ]]; then
		[[ -r $wg ]] || die "cannot read $wg"
		base=$(basename "$wg" .conf)
		name=$(echo "$base" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | sed 's/^-*//' | cut -c1-10)
		[[ -n $name ]] || name=vpn
		name=$(ask "Name for this tunnel" "$name")
		[[ $name =~ ^[a-z0-9][a-z0-9-]{0,9}$ ]] || die "name must be 1-10 chars: a-z 0-9 -"
		install -m600 "$wg" "$ETC/tunnels/$name.conf"
		ok "imported $wg as tunnel '$name' (PostUp/PreUp scripts in it are ignored)"
		if systemctl is-active -q "wg-quick@$base" 2>/dev/null; then
			warn "wg-quick@$base is running with the same config - two clients with one key fight each other"
			if yes_no "Stop and disable wg-quick@$base?" y; then
				systemctl disable --now "wg-quick@$base" && ok "wg-quick@$base stopped"
			fi
		fi
		tunnel_block=$(printf '[tunnel.%s]\nconfig = "%s/tunnels/%s.conf"\n' "$name" "$ETC" "$name")
		rule_hint="shunt run --via tunnel:$name -- firefox"
	fi
	cat >"$ETC/shunt.toml" <<EOF
# The Shunt configuration - docs: https://github.com/$REPO
# After editing: sudo systemctl reload shuntd   (or: shunt reload)

[daemon]
socket_group = "shunt"
# Where traffic goes that no rule matches: direct | block | tunnel:<name>
default_route = "direct"

[dns]
# Upstream for the direct route; default: your current system resolvers.
# direct = "pihole"

# [dns.upstream.pihole]
# addr = "192.168.1.2"                       # udp://, tcp://, tls://, https:// work too
# [dns.upstream.adguard]
# addr = "https://10.8.0.1/dns-query"
# tls_name = "adguard.example.org"

$tunnel_block
# DNS for a tunnel: the DNS= line of its WireGuard file, or set
# dns = "adguard" in its [tunnel.<name>] block.

# Rules - first match wins. Examples:
# [[rule]]
# name  = "SSH always direct"
# port  = ["tcp/22"]
# route = "direct"
#
# [[rule]]
# name   = "Streaming direct"
# domain = ["netflix.com", "nflxvideo.net"]
# route  = "direct"
EOF
	chmod 644 "$ETC/shunt.toml"
	ok "wrote $ETC/shunt.toml"
fi

if grep -qE '^hosts:.*\bresolve\b' /etc/nsswitch.conf 2>/dev/null; then
	warn "glibc asks systemd-resolved directly (nss-resolve) - that bypasses per-route DNS"
	if yes_no "Switch to plain DNS lookups? (backup is kept, undone on uninstall)" y; then
		"$BIN_DIR/shuntd" fix-nsswitch
	fi
fi

say "Dry run"
"$BIN_DIR/shuntd" -c "$ETC/shunt.toml" check >/dev/null 2>"$WORK/check.log" || {
	cat "$WORK/check.log"
	die "configuration check failed - fix $ETC/shunt.toml and run the installer again"
}
grep -v '^dns ' "$WORK/check.log" | sed 's/^/  /' || true
ok "configuration valid"

# ---------------------------------------------------------------- service
say "Starting the service"
install -m644 "$(unit_src shuntd.service)" "$UNIT"
install -m644 "$(unit_src shunt-lockdown.service)" "$LOCKDOWN_UNIT"
systemctl daemon-reload
systemctl enable -q shuntd.service
systemctl restart shuntd.service
step "waiting for shuntd" bash -c 'for _ in $(seq 50); do [[ -S /run/shunt/shuntd.sock ]] && exit 0; sleep 0.2; done; exit 1' || true
if ! systemctl is-active -q shuntd.service; then
	journalctl -u shuntd -n 30 --no-pager
	die "shuntd did not start. Emergency exit: sudo shuntd cleanup"
fi
ok "shuntd is running"
echo
"$BIN_DIR/shunt" status || true

cat <<EOF

${c_bld}Done.${c_off} Quick reference:
  ${rule_hint:-shunt run --via tunnel:<name> -- firefox}   start an app through a tunnel
  shunt status                       what is going on
  shunt panic on | off               cut everything / restore
  sudo nano $ETC/shunt.toml && shunt reload
  journalctl -u shuntd -f            logs

${c_yel}Stopping shuntd keeps the kill switch active (on purpose).${c_off}
Emergency exit:  sudo shuntd cleanup
Uninstall:       sudo bash install.sh --uninstall
Paranoid mode (block network at boot until shuntd runs):
                 sudo systemctl enable shunt-lockdown
EOF
[[ -n ${SUDO_USER:-} ]] && echo "Note: log out and in again so '$SUDO_USER' can use 'shunt' without sudo."
