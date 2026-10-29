#!/usr/bin/env bash
# The Windows Tor Expert Bundle we ship (packaging/windows/build.sh): pins in packaging/tor-versions.json.
#   verify   pinned sha256 is the one Tor signed: fetches sha256sums-signed-build.txt(.asc) of the pinned
#            version, checks the GPG signature against the Tor Browser Developers signing key
#            (fingerprint below, taken from https://support.torproject.org/tbb/how-to-verify-signature/ and
#            compared with the key's own fingerprint after import), and compares the pinned sha256.
#   newest   prints the newest Tor Browser version (the bundle has the same number)
# Needs: curl, gpg, jq. Exit != 0 on any mismatch.
set -euo pipefail
cd "$(dirname "$0")/../.."
KEY_FPR=EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
pin() { jq -r --arg k "$1" '.[$k]' packaging/tor-versions.json; }
case ${1:-verify} in
newest)
	curl -fsS https://aus1.torproject.org/torbrowser/update_3/release/downloads.json | jq -r .version ;;
verify)
	ver=$(pin tor-bundle-windows); sha=$(pin tor-bundle-windows-sha256)
	export GNUPGHOME; GNUPGHOME=$(mktemp -d); trap 'rm -rf "$GNUPGHOME"' EXIT; chmod 700 "$GNUPGHOME"
	curl -fsS "https://keys.openpgp.org/vks/v1/by-fingerprint/$KEY_FPR" | gpg --batch --quiet --import 2>/dev/null
	got=$(gpg --batch --with-colons --fingerprint | awk -F: '/^fpr/ {print $10; exit}')
	[ "$got" = "$KEY_FPR" ] || { echo "signing key fingerprint is $got, expected $KEY_FPR" >&2; exit 1; }
	base=https://dist.torproject.org/torbrowser/$ver
	curl -fsS -o "$GNUPGHOME/sums" "$base/sha256sums-signed-build.txt"
	curl -fsS -o "$GNUPGHOME/sums.asc" "$base/sha256sums-signed-build.txt.asc"
	st=$(gpg --batch --status-fd 1 --verify "$GNUPGHOME/sums.asc" "$GNUPGHOME/sums" 2>/dev/null || true)
	grep -q "^\[GNUPG:\] VALIDSIG .* $KEY_FPR\$" <<<"$st" || { echo "signature of sha256sums-signed-build.txt ($ver) is not valid for $KEY_FPR" >&2; exit 1; }
	want=$(awk -v f="tor-expert-bundle-windows-x86_64-$ver.tar.gz" '$2==f {print $1}' "$GNUPGHOME/sums")
	[ "$want" = "$sha" ] || { echo "pinned sha256 $sha, signed list says '$want'" >&2; exit 1; }
	echo "tor expert bundle $ver: signature ok, sha256 matches" ;;
*) echo "usage: $0 verify|newest" >&2; exit 2 ;;
esac
