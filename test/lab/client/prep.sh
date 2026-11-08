#!/usr/bin/env bash
# Prepares the lab client (run as root inside it): Shunt from a .deb, the lab
# apps, bpftrace. The tunnel config comes separately (test keys stay out of git).
#
#   prep.sh <the-shunt_*.deb>   Debian/Ubuntu/Kali
#   prep.sh pacman [--from-source]   Arch/CachyOS: tools via pacman, Shunt via install.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export DEBIAN_FRONTEND=noninteractive

if [[ $1 == pacman ]]; then
	pacman -S --needed --noconfirm bpftrace bind openbsd-netcat curl tcpdump
	curl -fsSLo /tmp/install.sh https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/HEAD/install.sh
	bash /tmp/install.sh "${@:2}"
else
	apt-get update -q
	apt-get install -yq --no-install-recommends bpftrace dnsutils netcat-openbsd curl
	apt-get install -yq "$1"
fi
# the lab user runs shunt run/desktop/ui: socket_group = "shunt" in the lab configs
[[ -n ${SUDO_USER:-} ]] && usermod -aG shunt "$SUDO_USER"

# VirtualBox virtio NICs only accept frames for a foreign MAC in promiscuous mode. NetworkManager's
# default random/stable cloned MAC then breaks DHCP/ARP/tunnel replies. Instead of pinning the real MAC
# (which hides findings F01/F05), set promisc on the physical NICs (udev rule), so the random MAC stays testable.
# LAB_NM_MAC=permanent = old workaround (pin the real MAC) if promisc is not enough.
if command -v nmcli >/dev/null 2>&1 && [[ -d /etc/NetworkManager ]]; then
	# udev, not a NetworkManager dispatcher script: no dispatcher event (pre-up included) comes before
	# DHCP finishes, and with the random MAC and no promisc DHCP never finishes.
	cat >/etc/udev/rules.d/90-shuntlab-promisc.rules <<'EOF'
# lab only (see test/lab/client/prep.sh): promisc on physical NICs, before NetworkManager asks for DHCP
ACTION=="add", SUBSYSTEM=="net", SUBSYSTEMS=="pci|virtio", RUN+="/bin/sh -c 'ip link set %k promisc on'"
EOF
	udevadm control --reload 2>/dev/null || true
	rm -f /etc/NetworkManager/dispatcher.d/90-shuntlab-promisc /etc/NetworkManager/dispatcher.d/pre-up.d/90-shuntlab-promisc
	for d in /sys/class/net/*/device; do
		i=${d%/device}; i=${i##*/}
		ip link set "$i" promisc on 2>/dev/null || true
	done
	if [[ ${LAB_NM_MAC:-} == permanent ]]; then
		install -d /etc/NetworkManager/conf.d
		printf '[connection-shuntlab-mac]\nmatch-device=type:ethernet\nethernet.cloned-mac-address=permanent\n' \
			>/etc/NetworkManager/conf.d/90-shuntlab-mac.conf
	fi
	systemctl reload NetworkManager 2>/dev/null || true
fi

# lab apps: copies so their comm is the rule name (rules match on comm)
for n in labtun labdir labfree; do install -m755 /usr/bin/curl /usr/local/bin/$n; done
for n in labtun labdir labfree; do install -m755 /usr/bin/dig /usr/local/bin/$n-dig; done
for n in labtun labdir labfree; do install -m755 "$(readlink -f /usr/bin/nc)" /usr/local/bin/$n-nc; done
install -m755 /usr/bin/bash /usr/local/bin/labtun-sh # children must inherit the route

install -d /usr/local/lib/shuntlab
install -m644 "$HERE/trace.bt" /usr/local/lib/shuntlab/trace.bt
install -m755 "$HERE/trace.sh" /usr/local/lib/shuntlab/trace.sh

if [[ -f $HERE/intern.conf ]]; then
	install -m600 "$HERE/intern.conf" /etc/shunt/tunnels/intern.conf
	install -m644 "$HERE/base.toml" /etc/shunt/shunt.toml
	systemctl restart shuntd
fi
systemctl enable shuntd
shunt version || true
