# Defense (Linux)

Off by default. Switch on with `[defense] enabled = true` (see `packaging/shunt.toml.example`).
Nothing leaves the machine: events, bans and network memory stay local; logs name only the
network class, never an SSID, MAC or address.

## Network classes

`[[network]] class = "trusted" | "public" | "managed"`. No class, or a network without a
profile, counts as `public`.

| class | decoys | watching |
|---|---|---|
| public | on | everything |
| managed | off | everything |
| trusted | off | everything (quiet) |

## What runs where

- Decoys (`internal/defense`): TCP listeners on `decoy_ports`, bound to the physical uplink
  with the bypass mark, started only in `public` networks. A port that something else uses is
  skipped; ports below 1024 need `CAP_NET_BIND_SERVICE` (set in `shuntd.service`).
  With `[inbound]` on, the decoy ports are let through by the set `decoy_ports` in the main nft table.
- Blocking: nft table `shunt_defense` (sets `ban4`/`ban6` with timeout, `never4`/`never6`,
  input chain at priority -10). Gateway and system DNS servers are on the never list automatically.
  Removed again when the defense is switched off or shuntd stops.
- Scan/brute-force observation: the same table logs new inbound connections (rate limited) to
  NFLOG group 5302; shuntd counts connections to ports nothing listens on per source
  (`Manager.Observe`). Limit: brute force on a real service (for example SSH) is not seen this way.
- Sensors (`sniff_linux.go`): gateway MAC change (netlink neighbour events, ARP and NDP), a second DHCP
  server (passive AF_PACKET with a BPF filter, needs `CAP_NET_RAW`), DNS comparison (the network's
  resolvers and a public resolver on port 53 against DoH over the default route), evil twin (a known
  SSID with a new gateway MAC; the memory is a hashed file in the state directory).
  The captive portal check of the daemon is reported as an observation.
- Reputation lists (abuse.ch, CC0) are fetched twice a day while the `reputation` feature is on;
  the cache is `<cache dir>/defense`.

## API

`GET /v1/defense`, `GET /v1/defense/events?since=N`, `POST /v1/defense/config`,
`POST /v1/defense/unban` (config and unban need the manage permission). `GET /v1/status` carries
`defense: {heat, level, class}` while the defense is on.
