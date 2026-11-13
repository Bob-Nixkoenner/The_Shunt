#!/usr/bin/env bash
# Builds the own F-Droid repo from the signed fdroid APK.
#   packaging/fdroid/build-repo.sh <apk> <out-dir> [<dir with older APKs to keep>]
# Needs: fdroidserver (pip install fdroidserver), ANDROID_HOME with build-tools,
#   FDROID_KEYSTORE (the repo key, a file), FDROID_KEYSTORE_PASSWORD,
#   FDROID_REPO_URL (where the repo will be served, e.g. https://example.org/fdroid/repo).
# The repo key signs the index; keep it (new key = users must re-add the repo).
set -euo pipefail
apk=$(realpath "$1"); out=$2
here=$(cd "$(dirname "$0")" && pwd)
: "${FDROID_KEYSTORE:?}" "${FDROID_KEYSTORE_PASSWORD:?}" "${FDROID_REPO_URL:?}" "${ANDROID_HOME:?}"

# The repo key and its password live only in a private work directory that is
# removed on every exit (also after an error); $out gets only what is served.
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rm -rf "$out"; mkdir -p "$work/repo" "$work/metadata"
if [ -n "${3:-}" ] && [ -d "$3" ]; then cp "$3"/*.apk "$work/repo/" 2>/dev/null || true; fi
cp "$apk" "$work/repo/"
# keep the newest 6 APKs
(cd "$work/repo" && ls -v *.apk | head -n -6 | xargs -r rm -f)
cp "$here/metadata.yml" "$work/metadata/org.theshunt.app.yml"
cp "$FDROID_KEYSTORE" "$work/keystore.p12"
cat > "$work/config.yml" <<CFG
sdk_path: $ANDROID_HOME
repo_url: $FDROID_REPO_URL
repo_name: The Shunt
repo_description: The Shunt (F-Droid build)
repo_keyalias: repo
keystore: keystore.p12
keystorepass: $FDROID_KEYSTORE_PASSWORD
keypass: $FDROID_KEYSTORE_PASSWORD
keydname: CN=The Shunt repo, O=The Shunt
CFG
(cd "$work" && fdroid update --verbose)
# hand over only what is served (never the key or the config)
mkdir -p "$out"
cp -r "$work/repo" "$out/repo"
cp -r "$work/metadata" "$out/metadata"
chmod -R u+rwX,go+rX "$out"
