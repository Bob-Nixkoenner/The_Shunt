#!/usr/bin/env bash
# Prepares the lab client (run as root inside it): Shunt from a .deb, the lab
# apps, bpftrace. The tunnel config comes separately (test keys stay out of git).
#
#   prep.sh <the-shunt_*.deb>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -yq --no-install-recommends bpftrace dnsutils netcat-openbsd curl
apt-get install -yq "$1"

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
