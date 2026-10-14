#!/usr/bin/env bash
# Installs every package group of install.sh with this distribution's package
# manager (inside a container, as root) and checks the tools are there.
# CI: job "installer-packages"; locally:
#   docker run --rm -v "$PWD:/src:ro" archlinux bash /src/test/installer/packages.sh
set -euo pipefail
src=$(cd "$(dirname "$0")/../.." && pwd)
# only the helper/package part of the installer (functions, no actions)
sed -n '/^# -* helpers/,/^SRC_DIR=/p' "$src/install.sh" | grep -v '^SRC_DIR=' >/tmp/shunt-installer-fns.sh
# shellcheck source=/dev/null
source /tmp/shunt-installer-fns.sh
# shellcheck disable=SC2034 # used by the sourced functions
LOG=/tmp/shunt-installer-packages.log LOG_ON=1
: >"$LOG"
[[ -n $PM ]] || die "no package manager found"
echo "package manager: $PM"
if [[ $PM == pacman ]]; then pacman -Sy --noconfirm >/dev/null; fi # fresh container: empty database
if [[ $PM == apt ]]; then step "updating package lists (apt)" apt-get -y -q update; fi
for g in base polkit openvpn ssh go desktop desktop-build; do
	pkg_install "$g" "$g"
done
for c in nft wg curl fuser ssh-keygen openvpn go gcc pkg-config; do
	command -v "$c" >/dev/null || die "$c missing after install"
done
pkg-config --exists gtk+-3.0 webkit2gtk-4.1 || die "GTK/WebKitGTK development files missing"
echo "all package groups install on $PM"
