#!/usr/bin/env bash
# Traffic for lab test R11 (automated_chain + bait): what an agent framework does at machine speed.
# 1. nmap SYN scan of the client's low ports (a scan finding), 2. at once fetch the bait file /.env
# from the HTTP decoy (port 80), 3. at once log in to the decoy's login form with the password found
# there. Scan to login well under 20 s, handshake to login under 3 s (one curl per step).
# Usage: TARGET=<ip> [PORTS=1-1024] ./chain.sh
# Lab only: the bait credentials are the client's random lock credentials, they open nothing.
set -euo pipefail
. "$(dirname "$0")/common.sh"
need nmap; need curl; need_target
ports=${PORTS:-1-1024}
t0=$(date +%s)
echo "== 1. SYN scan $ports =="
sudo nmap -Pn -sS -p "$ports" --min-rate 2000 "$TARGET" | grep -E "open|scanned" || true
echo "== 2. bait file =="
env_body=$(curl -s -m 5 "http://$TARGET/.env" || true)
pw=$(printf '%s\n' "$env_body" | sed -n 's/^DB_PASSWORD=//p' | head -1)
user=$(printf '%s\n' "$env_body" | sed -n 's/^DB_USERNAME=//p' | head -1)
if [[ -z $pw ]]; then
	echo "no DB_PASSWORD in /.env (bait not served?)"
	exit 1
fi
echo "bait user $user, password of ${#pw} characters"
echo "== 3. login with the bait password =="
curl -s -m 5 -o /dev/null -w "login answer %{http_code}\n" --data-urlencode "username=$user" --data-urlencode "password=$pw" "http://$TARGET/login" || true
echo "chain done in $(( $(date +%s) - t0 )) s"
