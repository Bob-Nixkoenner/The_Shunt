#!/usr/bin/env bash
# Builds the Go core (package mobile) into app/libs/shunt-core.aar.
# Needs: Go and ANDROID_HOME with an NDK (sdkmanager "ndk;27.2.12479018");
# gomobile/gobind are tools of the Go module (go.mod "tool" lines).
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export PATH=$PATH:$(go env GOPATH)/bin # gomobile calls gobind
# gomobile runs javac itself: JAVA_HOME alone is not enough
if ! command -v javac >/dev/null; then
	for j in "${JAVA_HOME:-}" "$HOME/Android/jdk"; do
		[[ -n $j && -x $j/bin/javac ]] && { export JAVA_HOME=$j PATH=$j/bin:$PATH; break; }
	done
	command -v javac >/dev/null || { echo "javac not found: set JAVA_HOME to a JDK (17 or newer)" >&2; exit 1; }
fi
mkdir -p android/app/libs # not in git (only *.aar would be in it, and those are ignored)
go install golang.org/x/mobile/cmd/gobind
go tool gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -javapkg org.theshunt \
	-ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384" -o android/app/libs/shunt-core.aar ./mobile
echo "built android/app/libs/shunt-core.aar"
