ID=B02
TITLE="Systemresolver (getent, resolved) geht durch den Tunnel"
CLIENT='
getent hosts "$1" || true
resolvectl query "r-$1" 2>&1 | tail -1 || true
'
