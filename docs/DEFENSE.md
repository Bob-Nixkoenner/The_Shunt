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
  (`Manager.ObserveState`). Limit: brute force on a real service (for example SSH) is not seen this way.
- Sensors (`sniff_linux.go`): gateway MAC change (netlink neighbour events, ARP and NDP), a second DHCP
  server (passive AF_PACKET with a BPF filter, needs `CAP_NET_RAW`), DNS comparison (the network's
  resolvers and a public resolver on port 53 against DoH over the default route), evil twin (a known
  SSID with a new gateway MAC; the memory is a hashed file in the state directory).
  The captive portal check of the daemon is reported as an observation.
- Reputation lists (abuse.ch, CC0) are fetched twice a day while the `reputation` feature is on;
  the cache is `<cache dir>/defense`.

### Scan detection (Zeek-style states)

Every attempt on a port is an outcome like in Zeek's `conn.log`: `S0` (SYN seen, nothing answered;
what the NFLOG sensor sees before the drop), `REJ` (refused; decoy hits count as this), or OK.
Only S0/REJ are failures. Per source and 60 s window, three separate checks, each fires once:

| Check | Threshold (default) | Event |
|---|---|---|
| scan over many ports | distinct ports, any outcome >= `ScanPorts` (6) | `scan`, `mode=many_ports` |
| scan by refusals | distinct ports with S0/REJ >= `FailPorts` (4) | `scan`, `mode=failed_ports` |
| failures on few ports | S0/REJ count >= `BruteConns` (10) while ports < `ScanPorts` | `brute_force`, `mode=few_ports` |

The detail also carries `s0=<n> rej=<n>`. One scan event per source and window (a port scan that
is found as `failed_ports` first is not reported again as `many_ports`).

### TLS decoy: JA3

The decoy on port 443 reads the first bytes of a connection; a TLS ClientHello is parsed by a small
own parser (`ja3.go`) and reported as an observation `ja3=<md5>`. Format as in the Salesforce
specification (BSD-3-Clause, checked 2026-11-11): `SSLVersion,Ciphers,Extensions,Curves,PointFormats`,
decimal values, `-` between values, GREASE values (RFC 8701) left out, MD5 of the string. JA4+ is not
used (FoxIO licence 1.1: non-commercial only). A hash on a JA3 list is a `reputation` event with
severity high (`list=<name> ja3=<md5>`) and can ban the source like any listed address.

### Optional lists (`defense.reputation_sources`, default empty)

Nothing optional is downloaded unless it is named here:

| Name | URL | Content |
|---|---|---|
| `sslbl_ja3` | `sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` | JA3 digests, CSV `ja3_md5,Firstseen,Lastseen,Listingreason`; abuse.ch terms of use (CC0, as the lists above); kept 72 h |
| `et_compromised` | `rules.emergingthreats.net/blockrules/compromised-ips.txt` | one IPv4 per line; kept 48 h |

Emerging Threats licence, as read on 2026-11-11: the open ruleset folder carries `BSD-License.txt`
(Copyright 2003-2026 Emerging Threats, three-clause BSD: use and redistribution with or without
changes allowed if the notice stays; no endorsement). The download instructions page asks for at most
one download a day (more than hourly is discouraged, HTTP 429 gives a 30 minute cool-down); our updater
runs every 12 h. **Not stated:** the `blockrules/` IP lists carry no licence text of their own (the
file has no header), so the BSD text is only assumed to cover them. For that reason the source is
opt-in, downloaded by the user's machine from the original site (never bundled or mirrored), and the
choice stays with the user. Left out on purpose: `emerging-botcc.rules` and `emerging-dshield.rules`
(Suricata rules, not address lists) and `fwrules/emerging-Block-IPs.txt` (its header says it is built
from Spamhaus, DShield and abuse.ch data; Spamhaus is not used here).

### Pivot on a source

Click an address in the event list, the live window or the block list: the UI opens a detail view
of everything the service still keeps about it (timeline, kinds, ports, block state, Block/Unblock).
`GET /v1/defense/events?src=<ip>` returns up to 500 newest events of that address (oldest first);
`POST /v1/defense/ban` blocks it by hand (reason `manual`; refused with 409 for addresses on the
never list, and while the defense is off).

### Network reports

One report per network, kept in `<cache dir>/defense/reports.json` (mode 0600, written every 30 s
and on stop, at most 64 networks). Network = the hashed key the daemon already uses (never a name,
SSID or MAC). Per network: counts per kind, peak heat (the gauge starts at 0 in a new network),
first/last sighting, DNS redirection (`yes`/`none_seen`/`unknown`), captive portal, client isolation
(not measured: always `unknown`). Source addresses are stored already cut to /24 (IPv4) or /48 (IPv6),
at most 50 per network. "none seen" means watched without a finding, not proof. Nothing is sent
anywhere; the export button saves a copy (`?export=1`: key shortened to 8 characters).

## API

`GET /v1/defense`, `GET /v1/defense/events?since=N` (or `?src=<ip>`), `GET /v1/defense/reports[?export=1]`,
`POST /v1/defense/config`, `POST /v1/defense/ban`, `POST /v1/defense/unban` (config, ban and unban need the manage permission). `GET /v1/status` carries
`defense: {heat, level, class}` while the defense is on.
