ID=M08
TITLE="Endpunkt-IP:Port von einer direkten App erreichbar? (Info)"
EXPECT_CANARY=any
NOTE="Info-Test (Mullvad verbietet es): labdir sendet UDP an den Tunnel-Endpunkt. Das Paket ist am Gateway ohnehin als Tunnelverkehr erlaubt; Ergebnis steht in client.out."
CLIENT="EP='$(gw head -1 /etc/shuntlab/endpoints)'"'
ip=${EP%%:*}; rest=${EP#*:}; port=${rest%%/*}
echo x | labdir-nc -u -w1 "$ip" "$port" && echo "INFO labdir darf UDP an den Endpunkt $ip:$port"
echo x | labfree-nc -u -w1 "$ip" "$port" && echo "INFO labfree (Standardweg) darf UDP an den Endpunkt"
true
'
