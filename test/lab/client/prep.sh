#!/usr/bin/env bash
# Prepares the lab client (run as root inside it): Shunt from a .deb, the lab
# apps, bpftrace. The tunnel config comes separately (test keys stay out of git).
#
#   prep.sh <the-shunt_*.deb>   Debian/Ubuntu/Kali
#   prep.sh pacman [--from-source]   Arch/CachyOS: tools via pacman, Shunt via install.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export DEBIAN_FRONTEND=noninteractive

# An old snapshot has no udev rule yet (it is written further down): without promisc on the virtio NIC
# the DHCP/ARP replies for a random MAC never arrive and the first package download fails. So first of all.
for d in /sys/class/net/*/device; do
	[[ -e $d ]] || continue
	i=${d%/device}; i=${i##*/}
	ip link set "$i" promisc on 2>/dev/null || true
done

if [[ $1 == tarball ]]; then
	# non-Debian: tools via dnf/pacman, Shunt = files of the rk .deb unpacked on the host ($2 = tar of the deb data)
	if command -v dnf >/dev/null; then dnf -y -q install bpftrace bind-utils nmap-ncat curl tcpdump
	else pacman -S --needed --noconfirm bpftrace bind openbsd-netcat curl tcpdump; fi
	systemctl stop shuntd 2>/dev/null || true
	tar -C / -xf "$2"
	# what the .deb's postinst does besides unpacking: the group of the control socket and the config directories
	getent group shunt >/dev/null || groupadd --system shunt
	install -d -m755 /etc/shunt; install -d -m700 /etc/shunt/tunnels
	for b in shunt shuntd; do [[ -e /usr/local/bin/$b ]] && ln -sf /usr/bin/$b /usr/local/bin/$b; done
	sed -i 's|/usr/local/bin/shuntd|/usr/bin/shuntd|g' /usr/lib/systemd/system/shuntd.service 2>/dev/null || true
	rm -f /etc/systemd/system/shuntd.service /usr/local/lib/systemd/system/shuntd.service
	systemctl daemon-reload
elif [[ $1 == pacman ]]; then
	pacman -S --needed --noconfirm bpftrace bind openbsd-netcat curl tcpdump
	curl -fsSLo /tmp/install.sh https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/HEAD/install.sh
	bash /tmp/install.sh "${@:2}"
else
	apt-get update -q
	apt-get install -yq --no-install-recommends bpftrace dnsutils netcat-openbsd curl libglib2.0-bin
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
