#!/usr/bin/env bash
# Builds Debian packages from built binaries:
#   the-shunt_<ver>_<arch>.deb          shuntd + shunt, systemd units, polkit policy
#   the-shunt-desktop_<ver>_amd64.deb   tray app + window (needs GTK/WebKit), if BIN has shunt-desktop
# Usage: VERSION=v0.7.1-rc1 ARCH=amd64 BIN=<dir with shuntd shunt [shunt-desktop]> OUT=dist bash packaging/deb/build.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${VERSION:?set VERSION, e.g. v0.7.1-rc1}
ARCH=${ARCH:-amd64}
BIN=${BIN:?set BIN to the directory with the built binaries}
OUT=${OUT:-dist}; mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
DEBVER=${VERSION#v}; DEBVER=${DEBVER/-/\~} # 0.7.1-rc1 sorts before 0.7.1 as 0.7.1~rc1
# file names keep the "-": GitHub turns "~" into "." in release asset names,
# and SHA256SUMS (made before the upload) would no longer match them
FILEVER=${VERSION#v}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# --- the-shunt
P=$T/core
install -d "$P/DEBIAN" "$P/usr/bin" "$P/usr/sbin" "$P/lib/systemd/system" "$P/usr/share/polkit-1/actions" "$P/usr/share/doc/the-shunt"
install -m755 "$BIN/shuntd" "$BIN/shunt" "$P/usr/bin/"
ln -s ../bin/shuntd "$P/usr/sbin/shuntd" # sudo's secure_path
for u in shuntd.service shunt-lockdown.service; do
	sed 's|/usr/local/bin/|/usr/bin/|g' "packaging/systemd/$u" >"$P/lib/systemd/system/$u"
	chmod 644 "$P/lib/systemd/system/$u"
done
install -m644 packaging/polkit/org.theshunt.policy "$P/usr/share/polkit-1/actions/"
install -m644 packaging/shunt.toml.example "$P/usr/share/doc/the-shunt/shunt.toml.example"
install -m644 README.md LICENSE "$P/usr/share/doc/the-shunt/" 2>/dev/null || true
cat >"$P/DEBIAN/control" <<EOF
Package: the-shunt
Version: $DEBVER
Architecture: $ARCH
Maintainer: The Shunt <noreply@users.noreply.github.com>
Section: net
Priority: optional
Depends: nftables, iproute2, wireguard-tools, ca-certificates, psmisc, polkitd | policykit-1
Recommends: openvpn
Homepage: https://github.com/Bob-Nixkoenner/The_Shunt
Description: Per-app split tunneling with WireGuard and OpenVPN
 Decides per app, IP, port or domain which traffic goes through which VPN
 tunnel. Multi-hop, DNS per route, DNS filter, kill switch, network profiles.
 Config: /etc/shunt/shunt.toml (see /usr/share/doc/the-shunt/shunt.toml.example).
EOF
cat >"$P/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
	getent group shunt >/dev/null || groupadd --system shunt
	install -d -m755 /etc/shunt
	install -d -m700 /etc/shunt/tunnels
	if [ ! -f /etc/shunt/shunt.toml ]; then
		printf '# The Shunt configuration - see /usr/share/doc/the-shunt/shunt.toml.example\n\n[daemon]\nsocket_group = "shunt"\ndefault_route = "direct"\n' >/etc/shunt/shunt.toml
		chmod 644 /etc/shunt/shunt.toml
	fi
	# Privacy on foreign networks, as install.sh offers it: on by default,
	# written once (whoever deletes the file keeps it deleted on updates).
	NM_PRIVACY=/etc/NetworkManager/conf.d/90-shunt-privacy.conf
	if [ -d /etc/NetworkManager/conf.d ] && [ ! -f "$NM_PRIVACY" ] && [ ! -e /var/lib/shunt/nm-privacy-offered ]; then
		cat >"$NM_PRIVACY" <<'NMEOF'
# The Shunt: privacy on foreign networks (removed with the package; delete
# this file to switch it off, it is not written again).
# Settings in a connection profile itself still take precedence.
[device]
wifi.scan-rand-mac-address=yes

[connection]
# a different MAC on every Wi-Fi, but the same one each time you return
# (keeps router reservations and hotel logins working)
wifi.cloned-mac-address=stable
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false
ipv6.ip6-privacy=2
NMEOF
		nmcli general reload conf >/dev/null 2>&1 || true
		echo "The Shunt: Wi-Fi privacy on from the next connection (own MAC per network, no host name in DHCP): $NM_PRIVACY"
	fi
	install -d -m755 /var/lib/shunt
	touch /var/lib/shunt/nm-privacy-offered
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl enable shuntd.service >/dev/null 2>&1 || true
	# decides at boot from daemon.boot_lockdown (auto: only for a tunnel default route)
	systemctl enable shunt-lockdown.service >/dev/null 2>&1 || true
	systemctl restart shuntd.service >/dev/null 2>&1 || true
	echo "The Shunt is early beta software and not a 100% solution: running programs keep their route, some snap apps start in two steps, and apps may connect before they are routed. Check with 'shunt leaktest'."
	echo "The Shunt: add yourself to the group 'shunt' to use the CLI: sudo usermod -aG shunt \$USER"
fi
EOF
cat >"$P/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
	systemctl disable --now shuntd.service shunt-lockdown.service >/dev/null 2>&1 || true
fi
EOF
cat >"$P/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = remove ] || [ "$1" = purge ]; then
	NM_PRIVACY=/etc/NetworkManager/conf.d/90-shunt-privacy.conf
	if grep -q '^# The Shunt: privacy' "$NM_PRIVACY" 2>/dev/null; then
		rm -f "$NM_PRIVACY" /var/lib/shunt/nm-privacy-offered
		nmcli general reload conf >/dev/null 2>&1 || true
	fi
fi
if [ "$1" = purge ]; then rm -rf /etc/shunt /var/lib/shunt; fi
EOF
chmod 755 "$P/DEBIAN/postinst" "$P/DEBIAN/prerm" "$P/DEBIAN/postrm"
dpkg-deb --root-owner-group -Zxz -b "$P" "$OUT/the-shunt_${FILEVER}_${ARCH}.deb" >/dev/null
echo "$OUT/the-shunt_${FILEVER}_${ARCH}.deb"

# --- the-shunt-desktop
if [ -x "$BIN/shunt-desktop" ]; then
	D=$T/desk
	install -d "$D/DEBIAN" "$D/usr/bin" "$D/usr/share/applications" "$D/usr/share/icons/hicolor/scalable/apps" "$D/etc/xdg/autostart"
	install -m755 "$BIN/shunt-desktop" "$D/usr/bin/"
	sed 's|/usr/local/bin/|/usr/bin/|g' packaging/desktop/the-shunt.desktop >"$D/usr/share/applications/the-shunt.desktop"
	install -m644 packaging/desktop/the-shunt.svg "$D/usr/share/icons/hicolor/scalable/apps/"
	printf '[Desktop Entry]\nType=Application\nName=The Shunt (tray)\nExec=/usr/bin/shunt-desktop --hidden\nIcon=the-shunt\nTerminal=false\n' >"$D/etc/xdg/autostart/the-shunt.desktop"
	cat >"$D/DEBIAN/control" <<EOF
Package: the-shunt-desktop
Version: $DEBVER
Architecture: $ARCH
Maintainer: The Shunt <noreply@users.noreply.github.com>
Section: net
Priority: optional
Depends: the-shunt (= $DEBVER), libgtk-3-0, libwebkit2gtk-4.1-0
Homepage: https://github.com/Bob-Nixkoenner/The_Shunt
Description: The Shunt tray icon and window
 Tray icon with status, notifications and the web UI in its own window.
EOF
	dpkg-deb --root-owner-group -Zxz -b "$D" "$OUT/the-shunt-desktop_${FILEVER}_${ARCH}.deb" >/dev/null
	echo "$OUT/the-shunt-desktop_${FILEVER}_${ARCH}.deb"
fi
