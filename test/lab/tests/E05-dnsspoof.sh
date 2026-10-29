ID=E05
TITLE="Netz fälscht alle DNS-Antworten"
MODE=dnsspoof
ALLOW=(comm:labdir dns)
EXPECT_CANARY=any
CLIENT='
b=$(labtun -s -m8 http://example.com/ | head -c 200)
[[ $b == *"shuntlab gateway"* ]] && echo "FAIL Tunnel-App bekam die gefälschte Antwort"
b=$(labdir -s -m8 http://example.com/ | head -c 200)
[[ $b == *"shuntlab gateway"* ]] && echo "INFO direkte App bekam die gefälschte Antwort (erwartet)"
true
'
