#!/usr/bin/env bash
# TLS test server / stand-in MITM for the tls check (R08). Two private test CAs (A, B), a leaf for NAME from each.
# Usage: tlsmitm.sh init  NAME            create CA A, CA B and the leaves in $TLSDIR (default ~/tlsmitm)
#        tlsmitm.sh serve a|b NAME        start a TLS server on :443 with the leaf of CA A or B (stops a running one)
#        tlsmitm.sh fp a|b                print the SHA-256 of the issuer name DER (what shunt remembers as the pin)
#        tlsmitm.sh stop
# The server sends the leaf only, so the "last certificate of the chain" is the leaf and its issuer is the CA.
set -euo pipefail
. "$(dirname "$0")/common.sh"
need openssl; need python3
D=${TLSDIR:-$HOME/tlsmitm}
mkdir -p "$D"
stop() { [[ -f $D/srv.pid ]] && kill "$(cat "$D/srv.pid")" 2>/dev/null || true; rm -f "$D/srv.pid"; }
case ${1:-} in
init)
	NAME=${2:?NAME}
	for ca in a b; do
		openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Lab Test CA ${ca^^}" \
			-keyout "$D/ca-$ca.key" -out "$D/ca-$ca.pem" 2>/dev/null
		openssl req -newkey rsa:2048 -nodes -subj "/CN=$NAME" -keyout "$D/leaf-$ca.key" -out "$D/leaf-$ca.csr" 2>/dev/null
		printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$NAME" >"$D/ext-$ca"
		openssl x509 -req -in "$D/leaf-$ca.csr" -CA "$D/ca-$ca.pem" -CAkey "$D/ca-$ca.key" -CAcreateserial \
			-days 30 -extfile "$D/ext-$ca" -out "$D/leaf-$ca.pem" 2>/dev/null
	done
	echo "init ok: $D" ;;
serve)
	w=${2:?a|b}; NAME=${3:?NAME}
	stop
	[[ -f $D/leaf-$w.pem ]] || { echo "run init first" >&2; exit 2; }
	nohup python3 - "$D/leaf-$w.pem" "$D/leaf-$w.key" >"$D/srv.log" 2>&1 <<'PY' &
import http.server, socketserver, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"ok\n")
    def log_message(self, *a): pass
class S(socketserver.ThreadingTCPServer): allow_reuse_address = True
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
s = S(("0.0.0.0", 443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
	echo $! >"$D/srv.pid"; sleep 1; kill -0 "$(cat "$D/srv.pid")" && echo "serving CA ${w^^} leaf on :443" ;;
fp)
	python3 - "$D/leaf-${2:?a|b}.pem" <<'PY'
import sys, hashlib
from cryptography import x509
c = x509.load_pem_x509_certificate(open(sys.argv[1], "rb").read())
print(hashlib.sha256(c.issuer.public_bytes()).hexdigest())
PY
	;;
stop) stop ;;
*) echo "usage: $0 init|serve|fp|stop" >&2; exit 2 ;;
esac
