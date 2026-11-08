#!/usr/bin/env bash
# Checks the contents of built packages: a release without lyrebird (Tor bridges)
# must not go out unnoticed.
# Usage: bash packaging/check-package.sh dist/the-shunt_*.deb dist/the-shunt-windows-amd64.zip ...
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 <package>..." >&2; exit 2; }
rc=0
need() { # need <package> <listing> <regex>
	grep -Eq "$3" <<<"$2" || { echo "MISSING in $1: $3" >&2; rc=1; }
}
for f in "$@"; do
	case $f in
	*/the-shunt_*.deb | the-shunt_*.deb) l=$(dpkg-deb -c "$f")
		need "$f" "$l" ' ./usr/bin/shuntd$'
		need "$f" "$l" ' ./usr/libexec/shunt/lyrebird$' ;;
	*/the-shunt-windows-*.zip | the-shunt-windows-*.zip) l=$(unzip -Z1 "$f")
		need "$f" "$l" '^shuntd-win\.exe$'
		need "$f" "$l" '^tor/tor\.exe$'
		need "$f" "$l" '^tor/pt/lyrebird\.exe$' ;;
	*/shunt_linux_*.tar.gz | shunt_linux_*.tar.gz) l=$(tar tzf "$f")
		need "$f" "$l" '(^|/)lyrebird$' ;;
	*) echo "skipped (unknown kind): $f" >&2; continue ;;
	esac
	echo "checked: $f"
done
exit $rc
