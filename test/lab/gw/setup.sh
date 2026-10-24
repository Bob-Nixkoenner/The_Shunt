#!/usr/bin/env bash
# Turns a throwaway Ubuntu VM into the lab gateway, i.e. "the café Wi-Fi"
# every test client sits behind. Run as root inside the gateway VM:
#
#   NIC1 enp0s3  VirtualBox NAT   uplink to the internet
#   NIC2 enp0s8  intnet shuntlab  the lab LAN the test clients join
#
# Idempotent. Everything the lab needs afterwards goes through labctl.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
export DEBIAN_FRONTEND=noninteractive

echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
apt-get update -q
apt-get install -yq --no-install-recommends \
	dnsmasq unbound tcpdump tshark nmap p0f python3-scapy nftables iproute2 iputils-ping

# we run our own instances with generated configs
systemctl disable --now dnsmasq unbound unbound-resolvconf 2>/dev/null || true
# the stock AppArmor profiles only allow the stock paths; this VM is throwaway
for p in usr.sbin.unbound usr.sbin.dnsmasq; do
	[[ -f /etc/apparmor.d/$p ]] || continue
	ln -sf /etc/apparmor.d/$p /etc/apparmor.d/disable/$p
	apparmor_parser -R /etc/apparmor.d/$p 2>/dev/null || true
done
systemctl set-default multi-user.target
hostnamectl set-hostname shunt-lab-gw

# NetworkManager keeps its hands off the lab LAN
cat >/etc/NetworkManager/conf.d/90-shuntlab.conf <<'EOF'
[keyfile]
unmanaged-devices=interface-name:enp0s8
EOF
systemctl reload NetworkManager 2>/dev/null || true

install -d /etc/shuntlab /var/lib/shuntlab/run /var/lib/shuntlab/cap /var/log/shuntlab
install -m 755 "$HERE/labctl" /usr/local/sbin/labctl
install -m 755 "$HERE/labweb.py" /usr/local/lib/labweb.py
[[ -f /etc/shuntlab/mode ]] || echo normal >/etc/shuntlab/mode

cat >/etc/sysctl.d/90-shuntlab.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.enp0s8.accept_ra = 0
EOF
sysctl -q --system

for unit in dnsmasq unbound web; do
	case $unit in
	dnsmasq) cmd="/usr/sbin/dnsmasq -k --conf-file=/var/lib/shuntlab/run/dnsmasq.conf" ;;
	unbound) cmd="/usr/sbin/unbound -d -c /var/lib/shuntlab/run/unbound.conf" ;;
	web) cmd="/usr/bin/python3 /usr/local/lib/labweb.py /etc/shuntlab/mode /var/log/shuntlab/web.log" ;;
	esac
	cat >/etc/systemd/system/shuntlab-$unit.service <<EOF
[Unit]
Description=shunt lab $unit
After=network-online.target shuntlab-net.service
Requires=shuntlab-net.service

[Service]
ExecStart=$cmd
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
done

cat >/etc/systemd/system/shuntlab-net.service <<'EOF'
[Unit]
Description=shunt lab network (addresses, nftables, configs)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/labctl apply

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shuntlab-net shuntlab-dnsmasq shuntlab-unbound shuntlab-web
labctl mode "$(cat /etc/shuntlab/mode)"
labctl status
