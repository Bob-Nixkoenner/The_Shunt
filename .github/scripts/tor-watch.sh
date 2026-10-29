#!/usr/bin/env bash
# Compares the Tor stack we ship with the newest upstream releases (packaging/tor-versions.json)
# and opens one issue per new version. Needs: curl, jq, gh (GH_TOKEN). Used by tor-watch.yml.
# Usage: bash .github/scripts/tor-watch.sh [--dry-run]
set -euo pipefail
cd "$(dirname "$0")/../.."
DRY=${1:-}
pinned() { jq -r --arg k "$1" '.[$k]' packaging/tor-versions.json; }
GL=https://gitlab.torproject.org/api/v4/projects

# newest tor tag (tor-0.4.9.15 -> 0.4.9.15) and its tag message (the release notes' first lines)
tor_json=$(curl -fsS "$GL/tpo%2Fcore%2Ftor/repository/tags?per_page=30")
tor_new=$(jq -r '.[].name' <<<"$tor_json" | grep -E '^tor-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^tor-//' | sort -V | tail -1)
tor_msg=$(jq -r --arg t "tor-$tor_new" '.[] | select(.name==$t) | .message' <<<"$tor_json")

lyre_new=$(curl -fsS "$GL/tpo%2Fanti-censorship%2Fpluggable-transports%2Flyrebird/repository/tags?per_page=30" \
	| jq -r '.[].name' | grep -E '^lyrebird-[0-9.]+$' | sed 's/^lyrebird-//' | sort -V | tail -1)

# tor-android: newest tag of the Guardian Project's wrapper (the libtor.so the Android app embeds)
android_new=$(curl -fsS "https://api.github.com/repos/guardianproject/tor-android/tags?per_page=1" | jq -r '.[0].name')

issue() { # component, old, new, security(0/1), notes
	local comp=$1 old=$2 new=$3 sec=$4 notes=$5 title labels=dependencies
	title="Tor stack: $comp $new available (we ship $old)"
	[ "$sec" = 1 ] && { title="SECURITY: $title"; labels="dependencies,security"; }
	if [ "$DRY" = --dry-run ]; then echo "would open: $title"; return; fi
	gh label create dependencies --color 0366d6 2>/dev/null || true
	gh label create security --color d73a4a 2>/dev/null || true
	if [ -n "$(gh issue list --state all --search "\"$comp $new available\" in:title" --json number --jq '.[0].number')" ]; then
		echo "issue for $comp $new exists"; return
	fi
	gh issue create --title "$title" --label "$labels" --body "$(cat <<BODY
**$comp**: pinned $old, newest upstream $new.
$( [ "$sec" = 1 ] && echo "The release notes mention security fixes: do this first." )

$notes

Checklist
- [ ] Read the release notes and decide how urgent it is (security: patch before anything else)
- [ ] Bump \`packaging/tor-versions.json\` and the real pins: tor-android dependency in \`android/app/build.gradle.kts\`, \`packaging/pt/go.mod\` (lyrebird: see \`packaging/pt/build.sh\`), Linux \`tor\` package floor in \`packaging/deb\`
- [ ] Build Android and Linux (release workflow, .deb, installer)
- [ ] Emulator tests for Tor (\`android-tor-plan.md\`) and the Linux Tor lab tests (\`tor-socks-plan.md\`)
- [ ] Do not forget lyrebird (bridges): it ships in the release archive, the .deb and the installer, and on Android next to \`libtor.so\`
- [ ] CHANGELOG line
BODY
)"
}

# security hint: the release notes (tag message) of tor name security fixes
sec=0; grep -qiE 'security|CVE-|TROVE-|denial of service|remote crash' <<<"$tor_msg" && sec=1

[ "$(printf '%s\n%s\n' "$(pinned tor)" "$tor_new" | sort -V | tail -1)" != "$(pinned tor)" ] && \
	issue tor "$(pinned tor)" "$tor_new" "$sec" "Release notes: https://gitlab.torproject.org/tpo/core/tor/-/blob/main/ReleaseNotes (tag tor-$tor_new). Tag message starts: $(head -c 400 <<<"$tor_msg" | tr '\n' ' ')"
[ "$lyre_new" != "$(pinned lyrebird)" ] && [ "$(printf '%s\n%s\n' "$(pinned lyrebird)" "$lyre_new" | sort -V | tail -1)" = "$lyre_new" ] && \
	issue lyrebird "$(pinned lyrebird)" "$lyre_new" 0 "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/tags"
[ "$android_new" != "null" ] && [ "$android_new" != "$(pinned tor-android)" ] && \
	issue tor-android "$(pinned tor-android)" "$android_new" 0 "https://github.com/guardianproject/tor-android/tags (the Guardian Project builds libtor.so; its tor version may lag the newest tor)"

# Windows Tor Expert Bundle (packaging/windows/build.sh): newest Tor Browser version, and the pin must verify
# (sha256 against the list Tor signed, signature of the Tor Browser Developers key)
bundle_new=$(bash .github/scripts/tor-bundle.sh newest)
[ "$bundle_new" != "$(pinned tor-bundle-windows)" ] && [ "$(printf '%s\n%s\n' "$(pinned tor-bundle-windows)" "$bundle_new" | sort -V | tail -1)" = "$bundle_new" ] && \
	issue "Windows Tor Expert Bundle" "$(pinned tor-bundle-windows)" "$bundle_new" "$sec" "Bundle: https://dist.torproject.org/torbrowser/$bundle_new/ . New pin: sha256 from sha256sums-signed-build.txt (verify the signature: \`bash .github/scripts/tor-bundle.sh verify\` after editing \`tor-bundle-windows\` and \`tor-bundle-windows-sha256\` in packaging/tor-versions.json). The bundle brings its own tor.exe and lyrebird.exe: check the Windows lab tests (Tor route, bridges)."
if ! out=$(bash .github/scripts/tor-bundle.sh verify 2>&1); then
	issue "Windows Tor bundle pin" "$(pinned tor-bundle-windows)" "does not verify" 1 "\`tor-bundle.sh verify\` failed: $out"
fi
# lyrebird: the pinned commit in packaging/pt/go.mod must be the one of tag lyrebird-<pinned>
lyre_commit=$(curl -fsS "$GL/tpo%2Fanti-censorship%2Fpluggable-transports%2Flyrebird/repository/tags/lyrebird-$(pinned lyrebird)" | jq -r .commit.id)
if ! grep -q "lyrebird v0.0.0-[0-9]*-${lyre_commit:0:12}" packaging/pt/go.mod; then
	issue "lyrebird pin" "$(pinned lyrebird)" "differs from packaging/pt/go.mod" 0 "tag lyrebird-$(pinned lyrebird) is commit $lyre_commit, go.mod pins something else."
fi
echo "tor $(pinned tor) -> $tor_new, lyrebird $(pinned lyrebird) -> $lyre_new, tor-android $(pinned tor-android) -> $android_new"
