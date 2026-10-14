#!/usr/bin/env bash
# Builds the Go core (package mobile) into app/libs/shunt-core.aar.
# Needs: Go and ANDROID_HOME with an NDK (sdkmanager "ndk;27.2.12479018");
# gomobile/gobind are tools of the Go module (go.mod "tool" lines).
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export PATH=$PATH:$(go env GOPATH)/bin # gomobile calls gobind
go install golang.org/x/mobile/cmd/gobind
go tool gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -javapkg org.theshunt \
	-ldflags "-s -w" -o android/app/libs/shunt-core.aar ./mobile
echo "built android/app/libs/shunt-core.aar"
