#!/usr/bin/env bash
# Self test for tools/opsec-scan.sh. Builds a throw-away git repo in a temp
# dir, with sample values assembled from fragments (so this file itself stays clean).
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scan="$here/opsec-scan.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp" "$tmp.priv"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

cd "$tmp" && git init -q . && git config user.email t@example.com && git config user.name t
printf 'hello\n' > clean.txt
git add . && git commit -qm clean
export OPSEC_ALLOW="$here/opsec-allow.txt" OPSEC_PATTERNS="$tmp.priv" OPSEC_MAILMAP="$tmp/none"
printf 'zq%sxy==>placeholder\n' secretword > "$tmp.priv"

OPSEC_PATTERNS=/nonexistent "$scan" >/dev/null 2>&1 && ok "clean tree exits 0" || bad "clean tree exits 0"

at=@; d=.
printf 'mail: jane%sprivate%scom\n'            "$at" "$d" >  dirty.txt
printf 'ip: 10%s20%s30%s40\n'                  "$d" "$d" "$d" >> dirty.txt
printf 'pub: 52%s1%s2%s3\n'                    "$d" "$d" "$d" >> dirty.txt
printf 'mac: 3c:52:%s\n' 82:11:22:33                            >> dirty.txt
printf 'path: /home/%s/x\n'                    realperson     >> dirty.txt
printf 'tok: ghp_%s\n' "$(printf 'A%.0s' $(seq 36))"           >> dirty.txt
printf 'priv: zq%sxy here\n' secretword                        >> dirty.txt
printf 'allowed: bob%sisst%spizza 192%s0%s2%s5 /home/user\n' "$at" "$d" "$d" "$d" "$d" >> dirty.txt
git add . && git commit -qm dirty

out=$("$scan" 2>&1); rc=$?
[ $rc -eq 1 ] && ok "dirty tree exits 1" || bad "dirty tree exits 1 (rc=$rc)"
for k in email ipv4 ipv4-private mac home token private; do
  grep -q "dirty.txt:[0-9]* \[$k\]" <<<"$out" && ok "detects $k" || bad "detects $k"
done
grep -qE 'jane|realperson|secretword|10\.20|ghp_A' <<<"$out" && bad "output is masked" || ok "output is masked"
grep -q 'dirty.txt:8 ' <<<"$out" && bad "allowlist honoured" || ok "allowlist honoured"

"$scan" --no-private 2>&1 | grep -q '\[private\]' && bad "--no-private" || ok "--no-private"

git rm -q dirty.txt && git commit -qm "remove"
"$scan" >/dev/null 2>&1 && ok "tree clean after removal" || bad "tree clean after removal"
"$scan" --history >/dev/null 2>&1 && bad "history still finds old commit" || ok "history still finds old commit"

[ $fail -eq 0 ] && echo "all tests passed" || { echo "tests FAILED"; exit 1; }
