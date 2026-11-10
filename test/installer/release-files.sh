#!/usr/bin/env bash
# Checks how install.sh takes the files of a signed release (no root, no
# network): the "# tag" line of SHA256SUMS must name the release it asked
# for, and the service files (systemd units, desktop entry, polkit policy)
# only come from the signed shunt_linux_extras.tar.gz. A fake release is
# served from a directory by a curl stub and signed with a fresh key.
#   bash test/installer/release-files.sh
set -euo pipefail
src=$(cd "$(dirname "$0")/../.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
# helpers (no actions) and the release functions of the installer
{
	sed -n '/^# -* helpers/,/^SRC_DIR=/p' "$src/install.sh" | grep -v '^SRC_DIR='
	sed -n '/^fetch_sums() {/,/^}/p; /^fetch_extras() {/,/^}/p; /^check_extras() {/,/^}/p' "$src/install.sh"
} >"$T/fns.sh"
grep -q '^check_extras() {' "$T/fns.sh" || { echo "release functions not found in install.sh"; exit 1; }

ssh-keygen -q -t ed25519 -N '' -C test -f "$T/key"
RELEASE_SIGNER="release@the-shunt $(cut -d' ' -f1-2 "$T/key.pub")"
RELEASE_NS=shunt-release
REPO=test/repo

# packaging files as release.yml packs them
mkdir -p "$T/pkg/systemd" "$T/pkg/desktop" "$T/pkg/polkit"
for f in systemd/shuntd.service systemd/shunt-lockdown.service systemd/shuntd-tailscale.conf \
	desktop/the-shunt.desktop desktop/the-shunt.svg polkit/org.theshunt.policy; do
	echo "test $f" >"$T/pkg/$f"
done

# mkrel tag taglines extras: a signed release served from $T/srv/<tag>.
# taglines: the "# tag" lines of SHA256SUMS ("" none);
# extras: good | tampered | unlisted | missing-file | not-served
mkrel() {
	local tag=$1 lines=$2 extras=$3 d=$T/srv/$1
	rm -rf "$d" && mkdir -p "$d"
	echo bin >"$d/shunt_linux_amd64.tar.gz"
	case $extras in
	missing-file) tar -czf "$d/shunt_linux_extras.tar.gz" -C "$T/pkg" systemd desktop ;;
	*) tar -czf "$d/shunt_linux_extras.tar.gz" -C "$T/pkg" systemd desktop polkit ;;
	esac
	(
		cd "$d"
		[[ -z $lines ]] || printf '%s\n' "$lines"
		if [[ $extras == unlisted ]]; then sha256sum shunt_linux_amd64.tar.gz; else sha256sum shunt_linux_amd64.tar.gz shunt_linux_extras.tar.gz; fi
	) >"$d/SHA256SUMS"
	ssh-keygen -Y sign -q -f "$T/key" -n "$RELEASE_NS" "$d/SHA256SUMS"
	[[ $extras != tampered ]] || echo evil >>"$d/shunt_linux_extras.tar.gz"
	[[ $extras != not-served ]] || rm "$d/shunt_linux_extras.tar.gz"
}

fail=0
# run name want-exit want-text env...: runs fetch_sums, fetch_extras and
# check_extras for release $tag in a fresh shell
run() {
	local name=$1 want=$2 text=$3 out rc
	shift 3
	rm -rf "$T/work" && mkdir -p "$T/work"
	out=$(env "$@" WORK="$T/work" T="$T" RELEASE_SIGNER="$RELEASE_SIGNER" RELEASE_NS="$RELEASE_NS" REPO="$REPO" \
		SHUNT_LANG=en bash -c '
		set -euo pipefail
		source "$T/fns.sh"
		LOG=$T/log LOG_ON=0
		curl() { # curl -fsSLo FILE URL: served from $T/srv
			local o=${@: -2:1} u=${@: -1}
			u=${u#https://github.com/$REPO/releases/download/}
			[[ -f $T/srv/$u ]] || return 22
			cp "$T/srv/$u" "$o"
		}
		fetch_sums
		PKG_DIR=$SRC_DIR/packaging
		fetch_extras
		check_extras
		echo "PKG_DIR=$PKG_DIR"
		cat "$PKG_DIR/polkit/org.theshunt.policy"
	' 2>&1) && rc=0 || rc=$?
	if [[ $rc != "$want" || $out != *"$text"* ]]; then
		echo "FAIL $name: exit $rc (want $want), output:"
		printf '%s\n' "$out" | sed 's/^/    /'
		fail=1
	else
		echo "ok   $name"
	fi
}

mkdir -p "$T/nosrc" "$T/checkout"
cp -r "$T/pkg" "$T/checkout/packaging"

mkrel v1.2.3 '# tag v1.2.3' good
run "signed release" 0 "test polkit/org.theshunt.policy" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
run "signed release, own installer" 0 "PKG_DIR=$T/work/packaging" tag=v1.2.3 REF=v1.2.3 SHUNT_RELEASE_INSTALLER=1 SRC_DIR="$T/checkout"

mkrel v1.2.3 '# tag v1.2.2' good
run "old release under a new tag" 1 "belong to release v1.2.2" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
run "old release under a new tag (named)" 1 "belong to release v1.2.2" tag=v1.2.3 REF=v1.2.3 SRC_DIR="$T/nosrc"
mkrel v1.2.3 $'# tag v1.2.3\n# tag v1.2.4' good
run "two tag lines" 1 "belong to release" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"

mkrel v1.2.3 '' good
run "no tag line, newest release" 1 "do not name the release" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
run "no tag line, own installer" 1 "do not name the release" tag=v1.2.3 REF=v1.2.3 SHUNT_RELEASE_INSTALLER=1 SRC_DIR="$T/nosrc"
run "no tag line, SHUNT_REF=<tag>" 0 "older release" tag=v1.2.3 REF=v1.2.3 SRC_DIR="$T/nosrc"

mkrel v1.2.3 '# tag v1.2.3' tampered
run "extras tampered" 1 "checksum mismatch (service files)" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
mkrel v1.2.3 '# tag v1.2.3' not-served
run "extras listed but not served" 1 "could not download the service files" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
mkrel v1.2.3 '# tag v1.2.3' missing-file
run "extras without the polkit policy" 1 "packaging/polkit/org.theshunt.policy is missing" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
mkrel v1.2.3 '# tag v1.2.3' unlisted
run "extras not signed, no checkout" 1 "has no signed service files" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"
run "extras not signed, from a checkout" 0 "PKG_DIR=$T/checkout/packaging" tag=v1.2.3 REF=HEAD SRC_DIR="$T/checkout"

# a wrong signature still stops everything
mkrel v1.2.3 '# tag v1.2.3' good
echo "# extra" >>"$T/srv/v1.2.3/SHA256SUMS"
run "signature wrong" 1 "signature of SHA256SUMS is wrong" tag=v1.2.3 REF=HEAD SRC_DIR="$T/nosrc"

# sha256sum -c skips the "# tag" line
mkrel v1.2.3 '# tag v1.2.3' good
if (cd "$T/srv/v1.2.3" && sha256sum -c --quiet SHA256SUMS); then echo "ok   sha256sum -c with the tag line"; else
	echo "FAIL sha256sum -c with the tag line"
	fail=1
fi
exit "$fail"
