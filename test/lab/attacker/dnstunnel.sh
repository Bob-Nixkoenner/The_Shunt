#!/usr/bin/env bash
# Long, high-entropy subdomains to a domain we control, to exercise DNS-tunnel detection.
# Usage: DOMAIN=<tunnel.example> [COUNT=20] ./dnstunnel.sh
set -euo pipefail
. "$(dirname "$0")/common.sh"
need dig
: "${DOMAIN:?set DOMAIN=<domain you control>}"
for ((i = 0; i < ${COUNT:-20}; i++)); do
	label=$(head -c24 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')
	dig +short +time=2 +tries=1 "${label}.${DOMAIN}" >/dev/null || true
done
