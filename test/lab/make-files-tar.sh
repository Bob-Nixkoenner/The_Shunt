#!/usr/bin/env bash
# Builds the tar that "lab.sh client-prep <file>.tar" unpacks into a non-Debian
# lab client (Arch, CachyOS, Fedora): the data of the Shunt .deb, in a layout
# that is safe on a merged-/usr system.
#
#   test/lab/make-files-tar.sh <the-shunt_*.deb> <out.tar> [arch|fedora|debian]
#
# Why not just tar up the .deb data: the .deb has ./lib/systemd/... and
# ./usr/sbin/shuntd. On Arch, CachyOS and Fedora /lib and /usr/sbin are
# symlinks. "tar -C / -xf" replaces such a symlink by a real directory and the
# machine no longer boots (emergency mode). So:
#   - ./lib/<x> is moved to ./usr/lib/<x>,
#   - ./usr/sbin is left out (the symlink in the .deb is only for sudo's
#     secure_path; /usr/sbin is /usr/bin there),
#   - the tar never contains an entry for ./lib itself, only for what is below.
# The same layout is safe on current Debian/Ubuntu (merged /usr), so the third
# argument only checks the spelling; it does not change the result.
set -euo pipefail
deb=${1:?usage: make-files-tar.sh <the-shunt_*.deb> <out.tar> [arch|fedora|debian]}
out=${2:?usage: make-files-tar.sh <the-shunt_*.deb> <out.tar> [arch|fedora|debian]}
case ${3:-arch} in arch | fedora | debian) ;; *) echo "unknown distro ${3}" >&2; exit 2 ;; esac
[[ -f $deb ]] || { echo "no such file: $deb" >&2; exit 2; }
[[ $out == *.tar ]] || { echo "the output must end in .tar (client-prep decides by the name)" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
dpkg-deb -x "$deb" "$tmp"

# what goes into the tar, relative to the .deb root (never ./lib itself)
items=()
for e in "$tmp"/* "$tmp"/.[!.]*; do
	[[ -e $e || -L $e ]] || continue
	n=${e##*/}
	case $n in
	lib) for c in "$e"/*; do [[ -e $c || -L $c ]] && items+=("./lib/${c##*/}"); done ;;
	*) items+=("./$n") ;;
	esac
done
((${#items[@]})) || { echo "the .deb has no files" >&2; exit 1; }

tar -C "$tmp" --exclude='./usr/sbin' --transform='s,^\./lib/,./usr/lib/,' -cf "$out" "${items[@]}"

# paranoia: nothing in the tar may replace a symlink of a merged-/usr system
bad=$(tar -tf "$out" | grep -x -E '\./(lib|bin|sbin|lib64|usr/sbin|usr/lib64)/?' || true)
if [[ -n $bad ]]; then
	echo "tar would replace a system symlink: $bad" >&2
	rm -f "${out:?}"
	exit 1
fi
echo "wrote $out ($(tar -tf "$out" | wc -l) entries)"
