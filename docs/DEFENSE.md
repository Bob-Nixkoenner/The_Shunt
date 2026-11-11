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
- Login decoys (feature `cowrie`): ports 23 and 2323 speak real telnet (RFC 854/857: the server sends
  IAC WILL ECHO and WILL SUPPRESS-GO-AHEAD, refuses other options, reads CR LF / CR NUL, asks
  `login:` / `Password:`, always answers `Login incorrect`, hangs up after 3 tries). Ports 22 and 2222 run a
  real SSH server (`golang.org/x/crypto/ssh`, BSD-3-Clause, now a direct dependency) with the banner
  `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` (`Decoys.SSHBanner`). Password and keyboard-interactive
  logins always fail; there is no public-key method, no shell, no exec, no channel. Limits: 16
  connections at once, 10 s per step, 6 tries per connection, 1 s pause after each refused try.
  Every try is one `cowrie` event with user name, password length and a 4-byte SHA-256 prefix, never
  the password. The ed25519 host key is created on first start in the defense directory
  (`ssh_host_ed25519_key`, mode 0600). 2222/2323 exist so there are decoys where a real sshd/telnetd
  holds 22/23 (a busy port is skipped); all listening decoy ports go into the nft set `decoy_ports`.
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
  Timing: the gateway's neighbour entry is compared on every netlink event and also every 5 s (events
  can be missed); the DNS comparison runs 3 s after joining, every 5 min, and right after a gateway MAC
  change (a finding is reported once until a clean run). The DHCP watch can also send a DHCP DISCOVER
  (random hardware address, broadcast flag, no host name, never a REQUEST) 4 s after joining and every
  5 min, so every server answers with a broadcast OFFER the listener sees; without it, it only sees replies
  to this machine's own requests. A second server ID raises `rogue_dhcp`.
  This probe sends into the network, so it is switchable with `defense.dhcp_probe`: `auto` (default) =
  only in public networks and never while the quiet mode (`daemon.quiet`, `quiet_out`) is on for the
  network; `on` = always (also in quiet mode, counts as explicit permission; not for trusted or managed
  networks you would rather keep silent); `off` = never, listen only. The Defense tab has the same choice.
  The daemon decides at network join and when the config changes (`defense.ProbeAllowed`); the nft
  `quiet_out` chain itself is not consulted, as AF_PACKET frames bypass it.
  Features missing from `[defense.features.*]` keep their default (watch on, block off).
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

### Spamhaus DROP / DROPv6 (documented, not built in)

Read 2026-11-11 (spamhaus.org/drop, drop-fair-use-policy, terms-conditions):
- Files: `drop_v4.json`, `drop_v6.json` (also `drop.txt`, said to be deprecated later); entries are a CIDR plus an SBL id; re-evaluated daily; "Please DO NOT auto-fetch the DROP list more than once per hour", elsewhere "not ... more than once per day".
- Terms 2.1: "provided to you free of charge subject to these Terms"; 2.2: "designed for use by firewalls and routing equipment".
- Terms 3.1: "protected by copyright and database right. Nothing in these Terms shall be construed as granting an assignment or licence of any intellectual property rights"; 3.3: Spamhaus may revoke the right to use "for any reason".
- 3.2: the name "Spamhaus" may not be used "in your marketing, promotional or any other commercial materials". 4.2: lists must be kept current.
- Nothing says whether an app may download it on the end user's machine (neither allowed nor forbidden), and no licence is granted.
- Decision: not built in. The UI shows the switch greyed out ("Terms require a separate agreement"); it can be added once Spamhaus agrees in writing. `defense.reputation_sources` refuses `spamhaus_drop`.

### Rules for sources

1. Nothing is bundled except the tiny documentation-range example list; the user's machine downloads every list from the provider itself.
2. Download over HTTPS through the default route (`downloadClient`, as `internal/blocklist`), neutral User-Agent `the-shunt`, 30 s time limit, 8 MiB size limit, at most every 12 h.
3. Every list has a maximum age (48 h, JA3 72 h). An older list, or one whose download keeps failing, expires and stops matching; the status shows the age and `expired`.
4. Every hit names its list (`list=<name>`).
5. Only high quality lists may block (`feodo`, `sslbl`, `sslbl_ja3`); `et_compromised` and any list with known false alarms only report, even when Block is on.
6. A hit can be allowed for good in the UI ("Always allow": adds the address to `defense.never` and lifts the block). Built-in lists are switched off with `defense.reputation_off`.

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

### Connection and DNS based detections

Each runs only while its feature switch (`dns_tunnel`, `beacon`, `first_seen`, `tls`) is on; none of them blocks.

| Feature | Where it is wired | What it does | Limits |
|---|---|---|---|
| `dns_tunnel` | `dnsproxy.Proxy.Observer` (optional interface, nil = proxy unchanged) calls `Manager.ObserveDNS` for every query; `Manager.ObserveDNSAnswer` for answered addresses | Per client and base domain (last two labels, a short list of two-part suffixes such as `co.uk`), queries of the last 60 s are scored by `DNSTunnelScore` (leftmost label length, entropy, TXT share); at 0.5 or more one `dns_tunnel` event (medium), then quiet for 10 min for that pair | Only what passes the Shunt's DNS proxy is seen (not DNS-over-HTTPS inside an app). The event names the base domain and the score, never the sub-domain labels. Up to 512 pairs are tracked |
| `beacon` | `daemon.defenseConnLoop` (Linux) reads TCP sockets in state ESTABLISHED/SYN_SENT every 10 s, skips sockets whose local port a program listens on, names the app from the cgroup (`sockets.Resolver`), calls `Manager.NoteConn`; `BeaconTracker` per (app, address:port) | 8 or more new connections, score 0.8 or more (`BeaconScore`) = one `beacon` event (low) per hour per pair, detail `app= interval= score=` | Connections shorter than 10 s can be missed, so beacons faster than about 20 s are not scored reliably. Exempt: ports 53, 67, 68, 123, 546, 547, loopback, the never list (gateway, DNS) and the programs `systemd-timesyncd`, `chronyd`, `ntpd`, `NetworkManager`, `systemd-resolved`, `dhclient`, `dhcpcd`, `avahi-daemon`, `packagekitd`, `fwupd`, `snapd` and `shuntd` (which also covers the updater and list downloads). A shared cgroup with several programs gives "unknown" |
| `first_seen` | same loop, `Manager.NoteConn` | Per app a set of known destinations (the base domain the proxy answered the address for, else /24 or /48; private, link-local and multicast ranges are not tracked). New destination after the app's 10 minute learning phase = `first_seen` (info, shown and counted, no heat, no block). At most 6 notes per minute; more are learned silently and counted as `more=N` in the next note | File `<cache dir>/defense/firstseen.json`, mode 0600, destinations stored as 8-byte hashes, at most 200 apps and 500 destinations per app (oldest dropped). The address-to-domain cache lives in memory (1 h, 4096 entries): after a restart a destination learned by domain is noted once more under its /24. Apps without a name (shared login session, `uid-N`) are not tracked |
| `tls` | `daemon.defenseTLSLoop` 20 s after start, 15 s after joining a network, then every 6 h; `defense.TLSChecker` | Handshake with each target over the default route; the remembered value is the SHA-256 of the issuer name of the last certificate in the chain (normally the root's name), up to 8 per target, in `tlspins.json` (0600, state directory). Leaf and intermediates are not compared (CDNs rotate them). First sight is pinned in a `trusted` network, or elsewhere only when a second path (DoH answer from 1.1.1.1/8.8.8.8, dialled by address, same server name) shows the same issuer. High events: issuer differs from the pin, the two paths disagree, or the chain does not verify against the system roots (public/managed only) | Without a pin and without a second path nothing is pinned and nothing is claimed. A pin that is no longer right (a CA really changed) raises the event until the network is marked trusted once or the pin file is removed; in a trusted network a new issuer is learned quietly. A network that intercepts all of port 443 consistently from the first sight on is only caught by a pin made elsewhere. Targets: `defense.tls_targets` (host names only, at most 16, default `api.github.com`, `www.wikipedia.org`); only public pages, nothing personal |

Windows and Android: no socket list is read and the TLS check is not started (the defense is Linux-only, the stubs
do nothing), so `beacon`, `first_seen` and `tls` are not available there; the DNS tunnel logic is platform
neutral but only runs where the daemon's DNS proxy feeds the defense.

## API

`GET /v1/defense`, `GET /v1/defense/events?since=N` (or `?src=<ip>`), `GET /v1/defense/reports[?export=1]`,
`POST /v1/defense/config`, `POST /v1/defense/ban`, `POST /v1/defense/unban` (config, ban and unban need the manage permission). `GET /v1/status` carries
`defense: {heat, level, class}` while the defense is on.
