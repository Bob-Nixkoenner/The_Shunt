#!/bin/bash
# outside-scan.sh - the server half of "Check from outside" (The Shunt).
#
# Run this on a server of YOUR OWN (a VPS, a container with its own public
# address). It scans exactly one address: the one the request came from, and
# nothing else. It takes no target from the client, no port list from the
# client, and refuses private/loopback/link-local/CGNAT addresses.
#
# Entry points (the source address comes from the connection, never from input):
#   CGI (nginx+fcgiwrap, Apache, lighttpd): REMOTE_ADDR is set by the web server.
#   ssh forced command:                     SSH_CLIENT is set by sshd.
#
# Answer (JSON): {"addr":"203.0.113.9","open":[22,80],"scanned":40}
# On refusal:    {"error":"..."}
#
# Settings (environment, all optional):
#   OUTSIDE_SCAN_TOKEN   shared secret; the client sends it in X-Shunt-Token
#                        (CGI: HTTP_X_SHUNT_TOKEN). Strongly recommended.
#   OUTSIDE_SCAN_PORTS   comma list of TCP ports (at most 100, default below)
#   OUTSIDE_SCAN_STATE   directory for the rate-limit stamps (default /var/lib/outside-scan)
#   OUTSIDE_SCAN_MINGAP  seconds between two scans of one address (default 60)
set -u
umask 077

MAX_PORTS=100
DEFAULT_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1723,2049,2222,2323,3306,3389,5432,5555,5900,5985,6379,8000,8080,8443,8888,9200,11211,27017,37215,49152,52869"
PORTS="${OUTSIDE_SCAN_PORTS:-$DEFAULT_PORTS}"
STATE="${OUTSIDE_SCAN_STATE:-/var/lib/outside-scan}"
MINGAP="${OUTSIDE_SCAN_MINGAP:-60}"
RATE=100 # packets per second, fixed upper bound

cgi=0
[ -n "${REMOTE_ADDR:-}" ] && cgi=1

out() { # status body
	if [ "$cgi" = 1 ]; then
		printf 'Status: %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n' "$1"
	fi
	printf '%s\n' "$2"
}
fail() { out "$1" "{\"error\":\"$2\"}"; exit 0; }

# 1. who is asking: only the connection's source address counts
if [ "$cgi" = 1 ]; then
	target="$REMOTE_ADDR"
elif [ -n "${SSH_CLIENT:-}" ]; then
	target="${SSH_CLIENT%% *}"
else
	fail 400 "no source address (run as CGI or ssh forced command)"
fi
# an argument is accepted only if it equals the source address (testing)
if [ "$#" -gt 0 ] && [ "$1" != "$target" ]; then
	fail 403 "the target must be the address the request came from"
fi
target="${target#::ffff:}" # IPv4-mapped form

# 2. token
if [ -n "${OUTSIDE_SCAN_TOKEN:-}" ]; then
	got="${HTTP_X_SHUNT_TOKEN:-${SHUNT_TOKEN:-}}"
	[ "${#got}" -eq "${#OUTSIDE_SCAN_TOKEN}" ] && [ "$got" = "$OUTSIDE_SCAN_TOKEN" ] || fail 403 "wrong token"
fi

# 3. the address must be a plain, routed, public one
fam=4
case "$target" in
*[!0-9a-fA-F:.]*) fail 400 "not an address" ;;
*:*) fam=6 ;;
esac
if [ "$fam" = 4 ]; then
	[[ "$target" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || fail 400 "not an address"
	a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]})) c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
	[ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ] || fail 400 "not an address"
	if [ "$a" -eq 0 ] || [ "$a" -eq 10 ] || [ "$a" -eq 127 ] || [ "$a" -ge 224 ] ||
		{ [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ]; } ||
		{ [ "$a" -eq 169 ] && [ "$b" -eq 254 ]; } ||
		{ [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } ||
		{ [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; }; then
		fail 403 "not a public address"
	fi
	addr="$a.$b.$c.$d"
else
	t="${target,,}"
	# global unicast 2000::/3 only (first hex digit 2 or 3); no ULA, link-local, loopback
	[[ "$t" =~ ^[23][0-9a-f]{0,3}: ]] || fail 403 "not a public address"
	[[ "$t" =~ ^[0-9a-f:]+$ ]] || fail 400 "not an address"
	addr="$t"
fi

# 4. the fixed port list (never from the client); cap and validate
IFS=',' read -r -a plist <<<"$PORTS"
[ "${#plist[@]}" -le "$MAX_PORTS" ] || fail 500 "server port list too long"
for p in "${plist[@]}"; do
	[[ "$p" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$p))" -ge 1 ] && [ "$((10#$p))" -le 65535 ] || fail 500 "bad port in the server list"
done
nports="${#plist[@]}"

# 5. at most one scan per address per MINGAP seconds
mkdir -p "$STATE" 2>/dev/null || STATE="${TMPDIR:-/tmp}/outside-scan"
mkdir -p "$STATE" 2>/dev/null
stamp="$STATE/$(printf '%s' "$addr" | tr ':' '_')"
now=$(date +%s)
if [ -f "$stamp" ]; then
	last=$(cat "$stamp" 2>/dev/null || echo 0)
	[[ "$last" =~ ^[0-9]+$ ]] || last=0
	[ $((now - last)) -ge "$MINGAP" ] || fail 429 "too soon, wait a minute"
fi
printf '%s' "$now" >"$stamp"

# 6. scan: TCP connect/SYN on the fixed list, one address, bounded rate and time
flag=""
[ "$fam" = 6 ] && flag="-6"
res=$(timeout 90 nmap $flag -Pn -n --max-retries 1 --max-rate "$RATE" --host-timeout 60s \
	-p "$PORTS" -oG - -- "$addr" 2>/dev/null) || fail 502 "scan failed"

# 7. open ports out of the greppable output: "Ports: 22/open/tcp//ssh///, ..."
open=$(printf '%s\n' "$res" | sed -n 's/^Host: .*Ports: //p' | tr ',' '\n' |
	sed -n 's|^ *\([0-9][0-9]*\)/open/.*|\1|p' | sort -n | paste -sd, -)
out 200 "{\"addr\":\"$addr\",\"open\":[${open}],\"scanned\":$nports}"
