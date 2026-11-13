#!/usr/bin/env bash
# Report H-02: which directory install.sh takes as its source checkout.
# Piped in: none (never the current directory). Run as a file: only a checkout
# that belongs to root or the sudo user and that nobody else may write to.
# Runs the SRC_DIR part of install.sh only (no root, no network).
set -euo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
block=$(sed -n '/^trusted_checkout() {/,/^SRC_DIR=.*$/p;/^if \[\[ -n \${BASH_SOURCE\[0\]:-} /,/^fi$/p' "$here/install.sh")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
mk() { mkdir -p "$1/cmd/shuntd" "$1/internal" "$1/packaging"; : >"$1/go.mod"; printf '%s\n' "$block" 'echo "SRC_DIR=[$SRC_DIR]"' >"$1/install.sh"; chmod -R go-w "$1"; }
check() { # name expected-substring got
	if [[ $3 == *"$2"* ]]; then echo "ok   $1"; else echo "FAIL $1: got $3"; fail=1; fi
}
export SUDO_USER=$(id -un)
# 1. piped from a directory that looks like a checkout
mk "$tmp/cwd"
got=$(cd "$tmp/cwd" && bash <"$tmp/cwd/install.sh" 2>&1)
check "piped: the current directory is not a checkout" "SRC_DIR=[]" "$got"
# 2. run as a file from a checkout others may write to
mk "$tmp/open"; chmod o+w "$tmp/open/cmd"
got=$(bash "$tmp/open/install.sh" 2>&1)
check "checkout writable by others: refused" "SRC_DIR=[]" "$got"
check "and said so" "is not used as a source checkout" "$got"
# 3. run as a file from the user's own clean checkout
mk "$tmp/mine"
got=$(bash "$tmp/mine/install.sh" 2>&1)
check "own clean checkout: used" "SRC_DIR=[$tmp/mine]" "$got"
exit $fail
