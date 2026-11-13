# Defense (Linux)

Off by default. Switch on with `[defense] enabled = true` (see `packaging/shunt.toml.example`).
Nothing leaves the machine: events, bans and network memory stay local; logs name only the
network class, never an SSID, MAC or address.

## Network classes

`[[network]] class = "unknown" | "unsafe" | "safe"` (German: Unklar / Unsicher / Sicher). No class, or a
network without a profile, counts as `unknown`: that is what a network you join for the first time is. The
window shows the class on the Defense tab (next to the alert-level gauge, with a list to change it for the network you
are in: the choice is stored in the [[network]] profile of this network, which is made when there is none)
and per profile under Configure, Networks ("network class"). Android stores the class per kind of network
(Wi-Fi, mobile).

| | Unknown (default) | Unsafe | Safe |
|---|---|---|---|
| meaning | new or not yet rated: find out | rated risky (cafe, hotel, guest) | home, workplace: calm |
| decoy ports | on | on | off |
| sensors (ARP, DHCP, DNS, TLS, ...) | on as the switches say | on as the switches say | on as the switches say |
| TLS check | reports | reports | learns a new issuer silently, no report for a foreign chain |
| active DHCP/DNS probe (`auto`) | yes (not in quiet mode) | yes (not in quiet mode) | no |
| blocking of scans, brute force, bad lists, DNS rebind | as the switches say (default: report only) | **on** while here (`defense.unsafe_block`, default true; the feature must still watch) | as the switches say |
| alert factor | 1.0 | 1.25 | 0.4 |
| block time | as configured (see Block time) | same | same |

Migration: the identifiers before 2026-11-12 are still read, in `shunt.toml`, in saved network reports, in the
evidence log (old lines keep their text) and in the Android settings, and mapped on reading: `public` ->
`unknown`, `trusted` -> `safe`, `managed` -> `safe`. A file is rewritten with the new names only when you save
a profile. `managed` and `trusted` were merged because their behaviour was the same except for the alert factor
(0.7 vs 0.4) and the TLS check: both ran no decoys and watched quietly. What changes for an old `managed`
network: lower alert level (0.4 instead of 0.7) and no TLS report for a chain the system roots do not trust (an
employer's TLS inspection used to raise that report). The "watch only, no decoys" of `managed` is exactly
what `safe` does. A network you want to keep strictly observed without decoys and quiet warnings does not
exist as a class any more; use `safe` and switch the single sensors in the Defense tab.

### Exposed: a public address on the uplink

Next to the class there is a trait, "exposed": an address of the uplink interface is neither private
(RFC 1918, ULA `fc00::/7`), link-local, loopback nor carrier-grade NAT (`100.64.0.0/10`) for IPv4, or a
global unicast address (`2000::/3`) for IPv6 (`netdetect.Info.PublicV4/PublicV6`, found per interface,
platform neutral; the documentation ranges count as public so tests can use them). It is independent of
the class: a trusted home network can have a public address too, and the machine behind a modem in
DMZ mode, a phone or a laptop with its own SIM is directly reachable.

Behaviour while exposed (`Status.exposed = {v4, v6, inbound}`):

- On entering (and when the inbound mode changes while exposed) the event `exposed` (severity high) says the
  device is directly reachable, naming the inbound mode of the profile in effect (`closed`, `lan`, `open` or
  `off` = The Shunt does not filter). `open`/`off` counts double for the alert level and the text is stronger. The UI
  shows a red plaque "Directly reachable from the internet" on the overview tile and the Defense tab; the
  tray app notifies (urgent when nothing filters). The warning needs the defense to be on.
- Decoys are **off**, also in a class that has them, unless `defense.decoys_when_exposed = true`: with a public
  address a decoy is real attack surface. (Hardening the decoys against exploits comes first.)
- Limits: events of one kind and source within 30 s are folded into the first one plus a line
  `more=N` (rare important kinds like ARP, DNS, TLS are never folded; heat and report counts still see
  every event; at most 2048 sources are tracked, beyond that events are only counted). Blocks go per range once
  4 addresses of one /24 (IPv4) or /64 (IPv6) are blocked (not if the range holds a never-block address such
  as the gateway, or an entry of `defense.ignore` at any trust step: own devices are never blocked, not even
  as part of a range). The ban table is capped at 4096 entries (the soonest-expiring one makes room). The
  event ring keeps 1000 events. The nft block sets are interval sets so a range is one element.

### Block time and escalation

A source that is blocked again waits longer each time. Config (all in seconds, also set in the Defense tab,
section "Blocked addresses"):

| Block of the same source | Key | Default |
|---|---|---|
| first | `ban_seconds` | 3600 (1 h; 0 = default; at most 30 days) |
| second | `ban_seconds_2` | 86400 (24 h; 0 = default) |
| third and every later one | `ban_seconds_3` | -1 = permanent, until lifted by hand (0 = default = permanent) |

-1 (until lifted by hand) is accepted for the second block too. Old configs with only `ban_seconds` keep
working: the new keys take their defaults. The count per source (or per blocked range) lives in memory for 30
days after its last block (8192 sources at most, oldest dropped) and is lost when shuntd restarts; a block
that is active right now does not raise the level. Manual blocks never escalate and use the first time.
`ban`/`unban` events say `level=N` and `permanent`; the block list shows the time left, "until you lift it" for
permanent ones.

Limits: a permanent block is an entry with a 10 year timeout in the same 4096-entry table, so it uses the same
space as any other. At most 1024 permanent entries exist at once; beyond that a block lasts 24 h instead, so
permanent blocks can never fill the table. Permanent blocks are not stored in a file: after a restart of shuntd
or a reboot the table is empty (as before). The lab configs (`test/lab/configs`) keep `ban_seconds = 300` on
purpose (short, so a test can see the lift) and are untouched; with them the second block lasts 24 h and the
third is permanent unless the lab config sets `ban_seconds_2`/`ban_seconds_3`.

### Outside check (your own server)

`[defense.outside_scan] enabled = true, host = "https://…/outside-scan", token = "…"`; off by default.
`POST /v1/defense/outside-scan` (manage permission) and the UI button "Check from outside (only with your own
server)" send one request, on the physical link outside any tunnel (bypass mark; per family that has a public
address), to that server. The client sends no target and no port list. The server
(`tools/outside-scan.sh`, run as CGI behind nginx+fcgiwrap or as an ssh forced command) connects back to the
**source address of the request only**, tries a fixed port list (at most 100, `nmap -Pn`, rate 100 packets/s,
60 s) and answers `{"addr":…,"open":[…],"scanned":N}`. The client refuses an answer whose address is not one
of this machine's own interface addresses, whose family does not match or that lists more than 100 or invalid
ports; the result is shown in the Defense tab and recorded as the event `outside` (high when ports answer).
Only your own server: the script refuses private/CGNAT/loopback sources, needs the token, and scans one address
per minute at most.

Server set-up (not done by The Shunt; example for a Debian container with a public address):
`apt install nmap fcgiwrap nginx`, copy the script to `/usr/local/bin/outside-scan.sh`, create
`/var/lib/outside-scan` (owner of the fcgiwrap user), and in nginx

```
location = /outside-scan {
    include fastcgi_params;
    fastcgi_pass unix:/run/fcgiwrap.socket;
    fastcgi_param SCRIPT_FILENAME /usr/local/bin/outside-scan.sh;
    fastcgi_param OUTSIDE_SCAN_TOKEN "change-me";   # same as defense.outside_scan.token
    # nginx must be the first hop: REMOTE_ADDR has to be the client's own address (no proxy in front)
}
```

nmap needs no root for a connect scan (`-sT` is used implicitly without privileges); with CAP_NET_RAW it uses SYN.
ssh variant: `command="OUTSIDE_SCAN_TOKEN=… /usr/local/bin/outside-scan.sh",restrict` in `authorized_keys` (the
script reads `SSH_CLIENT`); that variant is for manual tests, the client speaks HTTP only.

### Open ports (Port monitor)

`GET /v1/listening` marks a port `public` (red in the UI, with the program name) when it waits on all or a public
address, is not blocked or LAN-only by the inbound protection, and either nothing filters (inbound `open`/off) or
the uplink has a public address. A port that the closed inbound mode blocks is not red; the outside check is the
proof. Linux only: Windows and Android have no port list (the UI says so and points to the outside check).

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
  the password. The ed25519 host key is derived per network (see "Per-network decoy identity"
  below), so it differs between networks and stays the same in one network. 2222/2323 exist so there are decoys where a real sshd/telnetd
  holds 22/23 (a busy port is skipped); all listening decoy ports go into the nft set `decoy_ports`.
  HTTP decoy ports (80, 8080, 8000, 8888) show a fake login page and bait files, see
  "HTTP decoy, bait files and lock credentials" below.
- Blocking: nft table `shunt_defense` (sets `ban4`/`ban6` with timeout, `never4`/`never6`,
  input chain at priority -10). Gateway, system DNS servers and the addresses the tunnels talk to
  (WireGuard/OpenVPN peer endpoints, Tailscale peers with a direct path; read with the health check,
  at most 64) are on the never list automatically. Tor guards are not known and not listed.
  Ban spoofing: a scan ban needs only SYNs, and their source address can be forged. So replies to
  connections this machine opened always pass (`ct direction reply return` before the ban drop): a
  ban stops only what a source starts, never the tunnel or another own connection to that address.
  This machine's own addresses, multicast, broadcast, unspecified and 0.0.0.0/8 are never banned
  (`Manager.Bannable`; a manual ban answers 409).
  An automatic block for a scan or brute-force finding also **waits for a finished TCP handshake**
  with a decoy (`verify.go`): the finding is reported at once (detail `block=waits_for_handshake`),
  the block is carried out by the source's first real connection to a decoy within 10 minutes (ban
  detail `confirmed=handshake`); a handshake counts for 30 minutes. So a pure SYN scan (`nmap -sS`)
  is reported but not blocked until the scanner connects to a port it found open. Reputation hits
  and manual blocks are not held back. `defense.ban_unverified = true` restores blocking on packets
  alone (Defense tab, row "Port scans": "Block at once, without waiting for a real connection"; off by
  default, usable only while blocking of scans is on). Limit: someone who can read our SYN-ACK (same open Wi-Fi, on the path) can still finish a
  handshake under a forged address; the reply rule above then limits the damage.
  Internal errors: a panic in a decoy handler, sensor or packet reader is caught, counted and logged
  (`defense.Guard`, log line "internal error caught"); it costs one connection or one sensor round,
  not the daemon. The defense status shows a note when that happened.
  Limits against floods: at most 64 decoy handlers, 8 of them per source address; tarpit 32 traps,
  4 per source; ban table 4096 entries; scan detector 4096 sources with at most 1024 ports and
  256 failures each; event ring 1000. A decoy port survives accept errors (out of descriptors).
  Removed again when the defense is switched off or shuntd stops.
- Scan/brute-force observation: the same table logs new inbound connections (rate limited) to
  NFLOG group 5302; shuntd counts connections to ports nothing listens on per source
  (`Manager.ObserveState`). New TCP connections to a real open service are counted from the same log for
  `brute_service` (see "Brute force on real services" below).
- Sensors (`sniff_linux.go`): gateway MAC change (netlink neighbour events, ARP and NDP), a second DHCP
  server (passive AF_PACKET with a BPF filter, needs `CAP_NET_RAW`), DNS comparison (the network's
  resolvers against DoH over the default route and a public resolver asked through the tunnel), evil
  twin (a known SSID with a new gateway MAC; the memory is a hashed file in the state directory).
  The captive portal check of the daemon is reported as an observation.
  Timing: the gateway's neighbour entry is compared on every netlink event and also every 5 s (events
  can be missed); the DNS comparison runs 3 s after joining, every 5 min, and right after a gateway MAC
  change (a finding is reported once until a clean run). The DHCP watch can also send a DHCP DISCOVER
  (random hardware address, broadcast flag, no host name, never a REQUEST) 4 s after joining and every
  5 min, so every server answers with a broadcast OFFER the listener sees; without it, it only sees replies
  to this machine's own requests. After a gateway MAC change or a reconnect it is sent once more, 5 s
  after the trigger and at most once per 20 s. The wait is on purpose: the probe makes the gateway's
  DHCP server send ARP requests, which put the true gateway MAC back into the neighbour table for a
  few seconds; sent at once, that hid a DNS redirection from the DNS check that starts 2 s after the
  same trigger (lab R05). A second server ID raises `rogue_dhcp`.
  Known servers are the gateway address and the server of this client's own lease (read without root from
  NetworkManager `nmcli`, systemd-networkd or dhclient lease files; skipped when unreadable). The first
  server that answers while no known one has answered is only assumed to be the network's own (silently
  within 10 s after joining, later with an info note). A different server raises `rogue_dhcp` (high,
  "second server"). The assumption ends when a known server answers: then two servers answer, and the
  assumed one is reported, whichever of the two was faster and however much later the known one answers
  (lab R04: a rogue that answered the probe before the gateway was learned as the network's server and
  only its options were reported). A network whose DHCP server is not the gateway stays quiet, because
  its gateway does not answer DHCP at all; where the gateway and another server both answer, that is
  reported in either order. Limits: with a silent gateway and an unreadable lease, a rogue that answers
  before the real server makes the report name the real one; a rogue that puts the gateway's address
  into its server ID is not seen (the sender of the packet is not compared).
  This probe sends into the network, so it is switchable with `defense.dhcp_probe`: `auto` (default) =
  not in safe networks and never while the quiet mode (`daemon.quiet`, `quiet_out`) is on for the
  network; `on` = always (also in quiet mode, counts as explicit permission; not for safe
  networks you would rather keep silent); `off` = never, listen only. The Defense tab has the same choice.
  The daemon decides at network join and when the config changes (`defense.ProbeAllowed`); the nft
  `quiet_out` chain itself is not consulted, as AF_PACKET frames bypass it.
  The DNS comparison is an active probe as well: it asks `dns.google` and `one.one.one.one` at the
  network's own resolvers. Only these questions travel over the local network (they go to the
  resolvers that network named itself). `defense.dns_probe` (`auto` / `on` / `off`) works exactly like
  `dhcp_probe`; when it is not allowed, only the passive gateway-MAC watch runs (the DoH reference
  over the default route is not sent into the local network).
  The same names are also asked at 9.9.9.9, but only through the tunnel: the question carries the
  packet mark of the default route and is sent only while that route is a tunnel (not Tor, which
  carries no UDP). With the tunnel down the leak guard drops it like any other packet of that route;
  with a direct, block or link default route it is not sent at all. Until 2026-11-12 it went out over
  the local network with the bypass mark and showed that network a resolver and two names of the
  Shunt's choice (lab Q01/R03/R04).
  Order of one check: (1) the network's resolvers, every name; (2) 9.9.9.9 through the tunnel (after
  the first question without an answer the rest is skipped); (3) the DoH reference (at most 8 s per
  name). Everything that needs the tunnel comes after the local questions: whoever redirects DNS
  often cuts or delays the tunnel too, and asked first, the reference held the whole check until the
  real path was back (lab R05).
  What the local answers are compared with: the DoH reference; if it is out of reach, the answer
  from 9.9.9.9 through the tunnel (a live reference, full rating); if the tunnel carries nothing,
  the well-known addresses of `dns.google` and `one.one.one.one` (8.8.8.8/8.8.4.4, 1.1.1.1/1.0.0.1) -
  such a finding is rated medium and says so. A private or reserved answer of a network resolver for
  these names counts without any reference.
  If 9.9.9.9 through the tunnel and the DoH reference disagree, port 53 is answered by someone else
  at the tunnel's far end: `dns_hijack`, medium, "inside the tunnel". A reserved answer there (a
  filtering resolver of the VPN provider) is ignored. Not seen any more: a local network that leaves
  its own resolver alone but diverts port 53 to other resolvers - that could only be shown by sending
  such a question over the local network.
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

### HTTP decoy, bait files and lock credentials

Background: agent frameworks scan, try logins and use misconfigurations at machine speed; the advice
against them is decoys, tarpits and "fake wins". With the feature `cowrie` on, the decoy ports 80, 8080,
8000 and 8888 (of `decoy_ports`; the default list has 80) speak HTTP/1.x (`httpdecoy.go`):

- `/`, `/login`, `/admin` (and a few more) show a fake login page; a POST there (form or JSON, fields
  `username`/`user`/`login`/`email` and `password`/`pass`/`passwd`/`pwd`) is a login try like at the SSH
  and telnet decoys. Basic and Bearer credentials in the `Authorization` header count the same way.
- `/.env`, `/.git/config` and `/config.php.bak` are bait files. They carry the **lock credentials**: a
  user name, a 20-character password and a token, derived per network (below). No real service knows
  them; they open nothing.
- **Per-network decoy identity:** lock credentials and the ssh host key come from HKDF-SHA256 over one
  random secret of this installation (`<defense dir>/decoy-secret`, 32 bytes, mode 0600, never through a
  link, a damaged file is moved to `.bad`) and the key of the network the machine is in (a hash of
  interface, SSID and gateway, never stored or logged in clear). The same network gives the same ones
  after every restart; two networks give unrelated ones, so whoever fetches `/.env` or the host key in
  two places cannot tell it is the same device. Nothing is stored per network (forgetting a network
  leaves nothing behind). In gateway mode the decoys belong to the machine, so they use the network of
  its uplink. The fixed `bait.json` and `ssh_host_ed25519_key` of earlier versions are removed at start. Fetching a bait file is a `cowrie` event
  (medium, `bait=served`).
- Every other path answers 404 (`cowrie`, low, `path=` with at most 32 printable characters).
- Limits: 8 requests per connection, 64 KiB read per connection, 4 KiB of a form body looked at,
  10 s per request; the general decoy limits (64 handlers, 8 per source) apply.

Whoever presents the bait password or token at any login decoy (SSH, telnet, HTTP form, Basic or Bearer;
the user name does not matter) has read a bait file and uses what it found. That is a `bait` event,
**severity high** (`bait used via=ssh|telnet|http user=...`; the secret itself is never logged), and the
source is blocked at once when blocking of login attempts (`brute`, Block) is on - in unsafe networks
it is on by itself. No handshake wait: the source has finished one. Ignored devices (`defense.ignore`)
cause no `bait` event and no block. The comparison is constant-time.

A source on the ignore list as **known** or **test** (trust steps, see below) that uses the lock
credentials gets a `bait` event that is **shown only**: tagged `trust` in the event list, no
evidence-log entry, **never blocked**, also with blocking on and in unsafe networks. Decision of the
owner (2026-11-13): the user vouched for that device, for example an own scanner run against the
decoys; a device that should be blocked again must be taken off the list. The same holds for
`automated_chain`. Test: `TestTrustedSourceBaitAndChainShownNeverBlocked`.

### Tool marks (`tool=`)

The decoys read what a visitor sends anyway and name the program when it is a known scripted tool
(`tool.go`); the event detail then ends in `tool=<name>`:

| Where | Seen | Names |
|---|---|---|
| HTTP decoy | User-Agent | `nmap` (NSE), `curl`, `wget`, `python_requests`, `python_urllib`, `python_httpx`, `python_aiohttp`, `go_http`, `headless_chromium`, `playwright`, `puppeteer`, `masscan`, `zgrab`, `nikto`, `sqlmap`, `nuclei`, `gobuster`, `ffuf` |
| HTTP decoy | nmap's fixed 404 probe `/nice%20ports%2C/Tri%6Eity.txt%2ebak` | `nmap` |
| SSH decoy | client version | `nmap`, `python_paramiko`, `python_asyncssh`, `libssh` (hydra, medusa), `go_ssh`, `zgrab` |
| other decoy ports (no tarpit) | first bytes: nmap's SIP or 404 probe, or an HTTP request with such a User-Agent | as above; event `decoy_hit` low, detail `probe tool=<name>` |

A normal browser, OpenSSH or PuTTY gives no mark. An event with a mark adds 6 extra points to the
alert level (`heat` in the code; times the class factor), so a scripted visitor raises the gauge and its
alarms sooner. A mark of a test source adds nothing, one of a known source counts half like the rest
of its events. **A mark is
never a reason to block on its own**: the agent can change it in a second, and curl or a headless
browser are used by honest people too. The `probe` event is not fed to the scan detector (the
connection was already counted once).

In the Defense tab (`defDetail` in `internal/ui/static/defense.js`) the mark follows the event sentence
as "Tool: <name>" (a bare probe reads "Sent a probe of the tool ..."), with a hint that it never blocks;
`bait` reads "Bait credentials used" and `automated_chain` "Automated attack" (Android: `Defense.text`).

### Tempo: automated attack chains (`automated_chain`)

Agent frameworks run scan, connect and login in one go. The chain **scan finding -> finished
handshake with a decoy -> login try** (SSH, telnet, HTTP form/header, or the bait credentials) from
one source is reported as `automated_chain`, **severity high**, detail
`scan_to_login=<s> connect_to_login=<ms> via=ssh|telnet|http|bait`, when

| Condition | Threshold | From the lab |
|---|---|---|
| scan finding to login try | at most `ChainWindow` = 20 s | R01: nmap SYN + connect scan of 1024 ports at 500/s took 11 s, first full handshake 6.3 s after the scan finding |
| last handshake to login try | at most `ChainLoginGap` = 3 s | R02: scripted telnet login about 1 ms after the handshake; an SSH key exchange adds well under a second; a person typing a password needs longer |

R01 alone (no login) and R02 alone (logins, but only two ports, no scan finding) give no chain; the unit
test `TestAutomatedChain` holds both as controls. One finding per chain; half-done chains are forgotten
after 20 s and on a network change (at most 4096 sources followed). The source is blocked when blocking
of login attempts (`brute`, Block) is on, at once (it finished a handshake). Ignored devices
(`defense.ignore`) never start or finish a chain (the check sees only events that passed the list); a
known or test source can finish one, which is then shown only and never blocked (see the bait section), and
replies to this machine's own connections never make a scan finding (see below), so they cannot
start one. Limit: a person with a script (scan, then `sshpass`) is a chain as well - which is what it is.

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

### Brute force on real services (`brute_service`)

Guessing passwords at a service that really runs here (sshd, a web login, a database) does not show in
the scan detection, which counts only ports nothing listens on. `brute_service` counts it without touching
the service: nothing is delayed, answered, cut or proxied.

- **Input:** the packet log the table already has (NFLOG group 5302, the first packet of each new inbound
  connection, rate limited). No new nft rule, no new reader, no packet socket. A packet counts when it is a
  bare SYN (replies to own connections are skipped as for scans) to a TCP port that the **port monitor**
  ("Open ports", `shunt ports`) lists as open to the network: listening, not loopback-only, reachable from the
  uplink, not blocked by the inbound mode, not a decoy and not owned by The Shunt itself (proxy, DNS, UI). The
  list is read every 5 s outside the packet reader.
- **Why this way:** the existing sensors read NFLOG and the socket list; conntrack is already used by the
  daemon. A sniffer would see the same packets at higher cost; nft counters per source would need a dynamic
  set per address and still no handshake proof.
- **Short connections:** per source and port, one-second buckets over `SvcBruteWindow` = 60 s. Once a pair
  reaches the threshold, the connection table (conntrack, read only, at most once per second over all
  pairs and every 5 s per pair) is asked how many of that source's connections to the port are **still
  established**; those are not short and are subtracted. A client that keeps its connections (keep-alive
  pool, Syncthing, an SSH session) never adds up.
- **Thresholds (from the lab):**

| Finding | Short connections in 60 s on one port | From the lab |
|---|---|---|
| `brute_service`, medium | >= `SvcBruteConns` = 10 | R02 (run 2026-11-11 21:10): the scripted guesser (`brute.py`, one login per connection, no parallel tasks, N=10) sent 19 SYNs to telnet and 31 to ssh (with retransmissions and the port check) within its 30 s limit - the slowest scripted guessing seen. R01 (port scan): at most 5 SYNs on any one port; Q01-Q03 (no attacker): at most 2. Same number as `BruteConns` of the scan detection. |
| `brute_service`, high | >= `SvcBruteHigh` = 60 | one per second on average; hydra-like tools with 4-16 parallel tasks get there in seconds, a person who mistypes never does |
| nothing | a web client with 6 connections in 10 s (the browser limit per host); Syncthing-like long-running traffic; R01 (a port scan touches each port once or a few times); the Q runs (normal traffic of the test client) | unit tests `TestBruteServiceControls`, `TestBruteServiceLabR02` |

  Detail: `service=<program> conns=<n> short=<n> open=<n> window=60s handshake=yes|no|unknown`, plus
  `block=waits_for_handshake` when blocking is on and fewer than 10 handshakes were seen. One finding per pair and window;
  a medium finding can be followed by one high finding in the same window.
- **Blocking:** a **high** finding (60 short connections in a minute) blocks with at least 10 proven handshakes,
  a **medium** one only with at least `SvcBruteProven` = 20 (hydra keeps its connections open and tries several
  passwords on each: lab R10 gave `conns=25 short=10 open=15`, medium with 25 proven handshakes; an own device
  with a few short connections stays below 20; decision of the owner 13.11.). Only when blocking of login
  attempts (`brute`, Block; in unsafe networks automatic) is on **and** the connection table shows at least `SvcBruteConns` = 10 connections of that source with the port
  that finished a handshake (conntrack states ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK or TIME_WAIT;
  TIME_WAIT stays 120 s). One is not enough: a forger on the network could otherwise send SYNs in the name
  of a device that holds one real connection (a phone with Syncthing or SSH open) and get it blocked
  (`handshake=no` then). Bare SYNs (SYN_RECV, or CLOSE after a reset) are reported but **never block**; without a readable table (`handshake=unknown`)
  nothing is blocked either. A handshake seen here also confirms the source for blocks that waited for one
  (see "Ban spoofing").
- **Never counted:** ignored devices (`defense.ignore`) at every trust step (full, **known**, **test**: they are
  not even counted, so nothing is shown), the never list (gateway, system DNS servers, tunnel endpoints,
  `defense.never`), loopback, this machine's own addresses, peers that come in through a tunnel interface
  (point-to-point or without hardware address: WireGuard, OpenVPN tun, Tailscale), UDP. In the first 30 s
  after shuntd starts it only observes.
- **Memory and errors:** at most 8 ports per source and 2048 source/port pairs in total (60 counters each);
  a full table first drops pairs quiet for a window, else the new pair is not counted. Pairs are dropped
  after a quiet window and on a network change. A panic in the table read is caught (counted as unreadable);
  the packet reader itself runs under `defense.Guard`.
- **Limits:** a guesser slower than 10 connections a minute is not seen; one that keeps a single connection
  and tries many passwords inside it (SSH allows several per connection) shows as one connection - the
  service's own limit (`MaxAuthTries`) and its log are the place for that. Many sources with a few tries
  each (a botnet) stay below the threshold per source. The rate limit of the log rule (300/s) caps the
  counts in a flood; the finding comes all the same.
- **Lab:** test R10 (`test/lab/tests/R10-defense-brute-service.sh`, attacker script
  `attacker/brute-service.sh`) runs a hydra-like guesser from the Kali VM against the client's real sshd,
  with blocking on, and the two controls (6 web connections in 10 s; one long connection). Run it with
  `test/lab/run-defense-suite.sh --only R10`. Not run in a VM yet (2026-11-13).

### Ignored devices (`defense.ignore`) and false alarms from own traffic

`defense.never` only stops blocks ("Always allow"). The separate list `defense.ignore` (Defense tab, "Ignored devices") is for devices that must not be reported at all. An entry is `{addr, name, ports}`: `addr` an address or CIDR (IPv4 at least /8, IPv6 at least /32), `name` a note of the user (at most 64 printable characters), `ports` up to 16 local ports (empty = all ports). At most 64 entries; the config is refused otherwise.

- A source on the list causes no scan, brute-force or decoy event (tarpit and fake login included), so it also adds no alert level and cannot be blocked by those. The check runs before the detector counts the packet; an entry with ports only covers those ports.
- Reputation hits (known attacker lists) stay visible and can still block: being on the ignore list does not make a listed address harmless.
- **Trust steps.** An entry may carry `level` and `until`: `""` (default) = ignored completely as above; `"known"` = events from this source are shown (tagged `trust: "known"` in the event list) but not reported (no evidence-log entry), never blocked automatically (reputation hits excepted; they count normally), and count half for the alert level, which such sources can raise to 50 at most; `"test"` = same, but no alert level at all, and only until `until` (unix seconds, the UI sets now + 1 h; an end time more than 24 h after the config was loaded counts as 24 h), after that the source counts normally.
- **Naming.** The gauge is called *Alert level* (German *Alarmstufe*), 0-100, steps Quiet / Noticed / Elevated / Attack (*Ruhig / Bemerkt / Erhöht / Angriff*). Inside the code, API and config the word stays `heat` / `hot`. All visible words: `internal/i18n/lang/de.json`, `defLevelText` in `internal/ui/static/defense.js`, `levelLabel` in `Defense.kt`.
- A manual block still works. "Always allow" still adds to `defense.never`; both lists are shown and removable in the tab.
- VPN peers are **not** ignored or known automatically. Decision of the owner: a compromised device inside the VPN must keep standing out. Peers get on the list only when the user types them in.
- Replies to connections this machine opened never count as scan or brute force: the nft table skips replies that conntrack knows (`ct direction reply return`), and the packet reader additionally skips TCP packets with ACK or RST set (a connection attempt is a bare SYN). That covers answers whose conntrack entry is gone, for example right after a restart of shuntd. Limit: UDP answers without state are not told apart; bare ACK/RST packets of an attacker are not counted (the kernel drops them).
- In the first 30 s after shuntd starts the state is being rebuilt: scan and brute-force findings are only observed (not reported, not blocked). A scan that goes on is reported after the next window (60 s).

### Names of sources (silent)

The event list and the source detail show a host name next to the address when one is known. It is learned **silently**: nothing is sent (no reverse DNS, NetBIOS, mDNS or LLMNR question, no scan back). The sensor `hostNames` (`sniff_linux.go`, AF_PACKET with a BPF filter, IPv4, needs CAP_NET_RAW like the DHCP watch) only listens for packets other devices send on the segment anyway:

- DHCP client packets (UDP 68 to 67): option 12 (host name); the name belongs to ciaddr, else the requested address (option 50), else the packet source.
- mDNS (UDP 5353) and LLMNR (UDP 5355) announcements: address records (A, AAAA) whose address equals the packet's own source, so a device can name itself but not another one. mDNS names must end in `.local`, LLMNR names are single labels.
- A self-announced name (mDNS, LLMNR) ranks above a DHCP name. This machine's own addresses are skipped.

IPv6 mDNS/LLMNR is read since 2026-11-13 (`names6.go`, own filter, extension headers not followed). Not built: neighbour table (it has no names), NetworkManager or lease files (root files), the DNS proxy (it only knows names this machine asked for, not names of attackers).

A name is untrusted input, chosen by the device. It is cut to 63 characters, only printable characters are kept, and it lives in memory only (at most 512 entries, 24 h, forgotten on a network change). The API carries it as `names` in the events answer; the UI shows it as plain text marked "Name given by the device, not verified". It never decides anything (no block, no allow, no ignore). The evidence log lines never contain it; the export adds `source_names.json` for the sources of the export (with the same warning) and leaves it out when "Anonymize" is set.

### Pivot on a source

Click an address in the event list, the live window or the block list: the UI opens a detail view
of everything the service still keeps about it (timeline, kinds, ports, block state, Block/Unblock).
`GET /v1/defense/events?src=<ip>` returns up to 500 newest events of that address (oldest first);
`POST /v1/defense/ban` blocks it by hand (reason `manual`; refused with 409 for addresses on the
never list, and while the defense is off).

### Network reports

One report per network, kept in `<cache dir>/defense/reports.json` (mode 0600, written every 30 s
and on stop, at most 64 networks). Network = the hashed key the daemon already uses (never a name,
SSID or MAC). Per network: counts per kind, peak alert level (the gauge starts at 0 in a new network),
first/last sighting, DNS redirection (`yes`/`none_seen`/`unknown`), captive portal, client isolation
(not measured: always `unknown`). Source addresses are stored already cut to /24 (IPv4) or /48 (IPv6),
at most 50 per network. "none seen" means watched without a finding, not proof. Nothing is sent
anywhere; the export button saves a copy (`?export=1`: key shortened to 8 characters).

### Connection and DNS based detections

Each runs only while its feature switch (`dns_tunnel`, `beacon`, `first_seen`, `tls`) is on; none of them blocks.

| Feature | Where it is wired | What it does | Limits |
|---|---|---|---|
| `dns_tunnel` | `dnsproxy.Proxy.Observer` (optional interface, nil = proxy unchanged) calls `Manager.ObserveDNS` for every query; `Manager.ObserveDNSAnswer` for answered addresses | Per client and base domain (last two labels, a short list of two-part suffixes such as `co.uk`), queries of the last 60 s are scored by `DNSTunnelScore` (leftmost label length, entropy, TXT share); at 0.5 or more one `dns_tunnel` event (medium), then quiet for 10 min for that pair | Only what passes the Shunt's DNS proxy is seen (not DNS-over-HTTPS inside an app). The event names the base domain and the score, never the sub-domain labels. Up to 512 pairs are tracked |
| `beacon` | `daemon.defenseConnLog` (Linux) reads NFLOG group 5303: the output chain of the table `shunt_defense` logs the SYN of every new outgoing TCP connection (64 bytes, rate limit 100/s; not loopback, not to the never list, not ports 53/67/68/123/546/547; parser `ParseConnPacket`). The app comes from the socket at that moment (sock_diag + cgroup, at most 20 lookups per second, else unknown) and goes to `Manager.NoteConn`. Fallback: if the NFLOG group cannot be opened, `daemon.defenseConnLoop` reads the TCP sockets every 10 s instead (log line plus a note in the defense status); `BeaconTracker` per (app, address:port) | 8 or more new connections, score 0.8 or more (`BeaconScore`) = one `beacon` event (low) per hour per pair, detail `app= interval= score=` | Any connection counts, however short, and the time is the moment of the SYN. Limits: only TCP; connections beyond the rate limit are not seen (a flood); a beacon through a proxy or over one long connection is one connection; the owner is "unknown" when the socket is already gone at lookup. In the poll fallback, connections shorter than 10 s can be missed and beacons faster than about 20 s are not scored reliably. Exempt: ports 53, 67, 68, 123, 546, 547, loopback, the never list (gateway, DNS) and the programs `systemd-timesyncd`, `chronyd`, `ntpd`, `NetworkManager`, `systemd-resolved`, `dhclient`, `dhcpcd`, `avahi-daemon`, `packagekitd`, `fwupd`, `snapd` and `shuntd` (which also covers the updater and list downloads). A shared cgroup with several programs gives "unknown" |
| `first_seen` | same loop, `Manager.NoteConn` | Per app a set of known destinations (the base domain the proxy answered the address for, else /24 or /48; private, link-local and multicast ranges are not tracked). New destination after the app's 10 minute learning phase = `first_seen` (info, shown and counted, no alert level, no block). At most 6 notes per minute; more are learned silently and counted as `more=N` in the next note | File `<cache dir>/defense/firstseen.json`, mode 0600, destinations stored as 8-byte hashes, at most 200 apps and 500 destinations per app (oldest dropped). The address-to-domain cache lives in memory (1 h, 4096 entries): after a restart a destination learned by domain is noted once more under its /24. The app is the owner of the socket's cgroup (a socket does not tell its process, and shuntd has no `CAP_SYS_PTRACE` on purpose): the app of a scope or service, the only program of a shared cgroup, or - when several programs share one - the group as a whole, named `group:login-session` (any login, SSH or TTY session; a desktop without a scope per app lives there completely), `group:shunt:<path>` (a Shunt route group, for example `group:shunt:app/r1` for an app rule whose helpers carry other names) or `group:<unit>`. A group learns and is reported like one app; which of its programs opened the connection is not known. Everything started from a terminal counts as that terminal. The Shunt's own programs (`shuntd`, `shunt`, `shunt-desktop`, helpers) are never reported: their list downloads are no news. Until 2026-11-12 sockets of such groups had no name and were skipped without notice (lab R07). Still not tracked: sockets without any owner and `uid-N` |
| `tls` | `daemon.defenseTLSLoop` 20 s after start, 15 s after joining a network, then every 6 h; `defense.TLSChecker` | Handshake with each target over the default route; the remembered value is the SHA-256 of the issuer name of the last certificate in the chain (normally the root's name), up to 8 per target, in `tlspins.json` (0600, state directory). Leaf and intermediates are not compared (CDNs rotate them). First sight is pinned in a `trusted` network, or elsewhere only when a second path (DoH answer from 1.1.1.1/8.8.8.8, dialled by address, same server name) shows the same issuer. High events: issuer differs from the pin, the two paths disagree, or the chain does not verify against the system roots (public/managed only) | Without a pin and without a second path nothing is pinned and nothing is claimed. A pin that is no longer right (a CA really changed) raises the event until the network is marked trusted once or the pin file is removed; in a trusted network a new issuer is learned quietly. A network that intercepts all of port 443 consistently from the first sight on is only caught by a pin made elsewhere. Targets: `defense.tls_targets` (host names only, at most 16, default `api.github.com`, `www.wikipedia.org`); only public pages, nothing personal |

Windows and Android: no socket list is read and the TLS check is not started (the defense is Linux-only, the stubs
do nothing), so `beacon`, `first_seen` and `tls` are not available there; the DNS tunnel logic is platform
neutral but only runs where the daemon's DNS proxy feeds the defense.

### Network-level detections (features `dhcp_option`, `rogue_ra`, `dns_rebind`, `new_iface`)

These four only report (default: watch on, block off; blocking a source address makes no sense for
them). Source: `docs` of the attack-scenario catalogue (checked version, sources Q1 to Q14). Statements
marked **assumption** are not confirmed by that catalogue.

| Feature | Where | What it does | Limits |
|---|---|---|---|
| `dhcp_option` | `dhcp()` in `sniff_linux.go`, parser `defense.ParseDHCPOptions` (`dhcpopts.go`) on the same AF_PACKET socket as `rogue_dhcp`; the active DISCOVER probe only makes servers answer, so the OFFERs are read there too | Parses option 121 (classless static routes, RFC 3442) and option 249 (Microsoft classless routes; **assumption**: same encoding as 121), and notes which of 3/6/15/42/252 were offered. One info event per distinct option set (renewals stay quiet). **High** when a route is shorter than /8 but not a plain /0 (for example `0.0.0.0/1` plus `128.0.0.0/1`, the TunnelVision pattern, CVE-2024-3661) or a `/0` leads to a router other than option 3. The detail names option numbers and route prefixes, never gateway or resolver addresses | Option 3/6/15/42/252: what they mean for an attack is **assumption** (only 121 and the /1 pair are confirmed). Android does not apply option 121 (Q1) but the event is still raised. A malicious server can still win the race against the real one; this only tells you. Overloaded option fields (option 52) are not read |
| `rogue_ra` | `routerAdverts()` in `ra_linux.go`, parsers `ParseRA`/`ParseDHCPv6`, logic `raWatch` in `ra.go`; AF_PACKET (IPv6) with a BPF filter, `CAP_NET_RAW` | Router advertisements (ICMPv6 134; only valid ones: link-local source, hop limit 255): a second router with lifetime above 0 (medium; high when it also names DNS servers via RDNSS), a router address seen from a new hardware address (high), router lifetime 0 from a router that advertised a default route, a prefix with valid lifetime 0, RDNSS with lifetime 0 or a changed RDNSS set (medium; the lifetime-0 idea follows RFC 6104, **assumption** for what attackers do), more than 60 RAs in 10 s (flood), an RA behind a fragment header (pattern from RFC 7113). DHCPv6: two different servers (by server DUID) in Advertise/Reply (high) | RA-Guard (RFC 6105) is a switch feature, not a host switch; the kernel has no `ra_guard` setting. The host can watch (this) or set `accept_ra` (Q6); the Shunt does not change `accept_ra`. RAs behind hop-by-hop, routing or destination-option headers are not seen (BPF accepts only direct ICMPv6 and fragment headers). Two legitimate routers raise the "second router" note. DHCPv6 messages appear only when this machine asks. Router identity is the source address plus link-layer address; privacy extensions do not matter for routers |
| `dns_rebind` | `dnsproxy.Proxy` asks an Observer that also implements the optional `Rebinder` interface (`Manager.Rebind`) for each answered A/AAAA set, before the answer is cached or returned | Off unless `defense.rebind_protect = true`. A public name (not single-label, not `.local/.lan/.home/.internal/.localdomain/.home.arpa/.intranet/.corp/.private/.localhost/.test/.invalid`, not under `in-addr.arpa`/`ip6.arpa`, not under an entry of `defense.rebind_allow`) answered with a private (RFC 1918, fc00::/7), loopback, link-local, CGNAT (100.64/10) or unspecified address raises `dns_rebind` (medium, base domain and address class only, once per domain per 10 min). With the feature's **Block** switch on, the answer is dropped (REFUSED); otherwise only reported. A proxy without a defense behaves exactly as before | Only what passes the Shunt's DNS proxy is seen (not DoH inside an app). Unspecified (`0.0.0.0`) counts as hostile: this is common knowledge about rebinding, not in the catalogue (**assumption**). Public names that legitimately point inwards (split DNS) need `rebind_allow` |
| `new_iface` | `newIface()` in `iface_linux.go` (Linux only): netlink `RTM_NEWLINK` and `RTM_NEWROUTE` via `LinkSubscribe`/`RouteSubscribe`; classification `ClassifyIface` reads sysfs | An interface that was not there at the first start of the sensors raises `new_iface` once per name, with type (`ethernet`, `wlan`, `unknown`), bus (`usb` or none) and driver when readable (low; medium when `bus=usb`). A **default route** that goes over such an interface is **high**. Virtual devices (under `/sys/devices/virtual/net`: tunnels, veth, bridges) are ignored, so the Shunt's own tunnel never alarms. The event never names the interface (names like `enx<MAC>` carry the hardware address) | Netlink events for link and route are confirmed (Q9, Q12); that sysfs tells the bus (`device/subsystem` link to `usb`, a `usbN` path component) and the driver (`device/driver`, `uevent`) is an **assumption**, with the fallback "type unknown, no bus claim". The driver binds after the link appears, so it is read 1.5 s later. A DNS server handed out over the new interface is **not** detected yet. The real test with a Pi Zero 2 W as ECM/RNDIS gadget on a real device is still to be done together with the owner. Other platforms: stub |

Windows and Android: stubs only (no packet sockets or netlink). `dns_rebind` is platform neutral and works wherever the
DNS proxy runs with the defense.

## If shuntd no longer starts after a change

Every start is counted until shuntd has run for 30 seconds (or stopped in an orderly way). After 3 starts in a row with the same, newly saved config that never got there (a crash at start, as with Max Security and the system call filter on 2026-11-12), shuntd puts back the previous config (`shunt.toml.bak`, written by every save from the window or the CLI), keeps the failed one as `shunt.toml.failed`, logs it and shows a notice in the status. The previous config is never swapped back by itself, so there is no ping-pong. Without a different `.bak` (a config edited by hand) nothing is replaced. State: `start-guard.json` in the state directory.

## Evidence (Beweissicherung)

Goal: material you can hand to the police, a lawyer or an abuse desk. The Shunt records, it never attacks and **never scans back**. Off by default (`[defense.evidence] enabled`).

What is written (`<state dir>/defense/evidence/`, directory 0700, files 0600, UTC):
- `events-YYYYMMDD-NNN.jsonl`: one JSON line per event: `seq, time_utc, kind, severity, src (full address), port, proto, detail, shunt_version, net_class, prev_hash, hash`. Each line carries the SHA-256 of the line before it (hash chain across files and days); `chain.json` lists the files with the hash each starts from. Cases live in `cases.json`.
- State lines once per file and on change: clock sync (`state_clock`), clock jumps above 5 s (`clock_jump`, a manipulated time source is an attack too), network join and class (`state_net`).
- Not written: name, SSID, BSSID or MAC of the network (also scrubbed from free text), addresses of this machine, passwords (the fake login keeps length and a hash prefix only), and events that describe your own programs (`first_seen`, `beacon`, `observation`, `dns_tunnel`, `dns_rebind`).
- Retention: `retention_days` (90) and `max_mb`; oldest first; a kept (pinned) case is exempt until you delete it. "Delete all" removes everything (a second button also the kept cases). Removals are recorded in `chain.json`, so a gap is not mistaken for tampering.

Packet capture (`capture = true`, Linux only), pcapng for Wireshark/Zeek/Suricata:
- (a) first packet (cut to 128 bytes) of new inbound connections to decoy or closed ports, taken from the NFLOG group of the defense table (so by construction unsolicited); (b) incoming ARP, DHCPv4/v6 and ICMPv6 RS/RA/NS/NA frames (AF_PACKET with a BPF filter attached before binding). Never normal, outgoing or established traffic. The Shunt's own DNS/TLS probes are not captured (they cannot be told apart from normal traffic by a filter).
- A ring in memory (512 packets / 2 MiB) is the pre-roll; it reaches the disk only when an event of severity medium or higher happens (pre-roll plus 60 s), as `pcap/<time>-<seq>.pcapng`, each packet commented `event=<seq>`. `capture_max_mb` limits the directory. Control frames can contain hardware addresses of devices on the network: look before you share.

Export (button, or `POST /v1/defense/evidence/export`): `.tar.gz` with `events.jsonl`, `chain.jsonl` (hashes of every line in the span), `capture.pcapng`, `manifest.json` (SHA-256 of all files, period, time source, versions, OS and architecture, no host name), `README.txt` (method in plain words), `addresses.txt`/`addresses.csv` (for whois and similar; **the Shunt does not scan**) and, if `tsa_url` is set, `timestamp.tsr` (RFC 3161 over `manifest.json`; only the hash is sent, only on export). Check with `shunt evidence verify <archive|dir>` (reads files only); a `.tsr` is checked with `openssl ts -verify`.

Export per network: the window asks for the network first (list from `GET /v1/defense/evidence/networks`, labelled with the 8-character network label also shown in the network reports; no names exist in the log) and shows what the package will hold (`preview: true`) before anything is written. Only lines of that network go into `events.jsonl`; `chain.jsonl` still holds seq and hashes of the lines in between, which belong to other networks and sources (hashes only, no content, but their number and timing show that other lines exist). The service refuses an export without `net` unless `all_networks: true` is sent on purpose (the window never does). Networks are told apart by the label `net=<8 chars>` in the `net_enter` and `state_net` lines (new since 2026-11-12); older lines and lines before the first marker count as network `unknown`. A network joined again later is the same network (same label). Option `anonymize`: no `capture.pcapng` (control frames can hold this computer's hardware address) and no program, system or build details in `manifest.json`; the log lines themselves are never changed, because their hash chain would break (own addresses and hardware addresses are already left out when written).

Abuse contact (button, `GET /v1/defense/evidence/abuse?src=`): RDAP via the IANA bootstrap, then the registry of the range (never the address itself); operator, country, range, abuse e-mail; answer kept 7 days; neutral user agent, 10 s timeout, normal route, only on a button press.

Limits: whoever can rewrite all files on the machine can forge a consistent chain; the time stamp or a head hash given to someone earlier is the defence. VLAN-tagged control frames are not captured.

Legal note (no legal advice): IP addresses are personal data in many jurisdictions. Keeping them to report an offence is usually justified, keeping them longer is not; whether a record is usable in court depends on the case. Before acting on a serious finding ask the police or a lawyer. Scanning other people's machines can be illegal.

## API

`GET /v1/defense`, `GET /v1/defense/events?since=N` (or `?src=<ip>`), `GET /v1/defense/reports[?export=1]`,
`POST /v1/defense/config`, `POST /v1/defense/ban`, `POST /v1/defense/unban` (config, ban and unban need the manage permission). `GET /v1/status` carries
`defense: {heat, level, class, exposed, exposed_inbound}` while the defense is on. `POST /v1/defense/outside-scan` runs the outside check (manage permission; 409 when off or no public address, 429 while one runs).

## Windows and Android: Android (the watcher)

On Android the defense is a watcher, not a trap: no root, no decoy listeners, no packet sockets, no firewall (the phone
sits behind NAT and the VPN anyway). The sentence "Windows and Android: Linux-only" above no longer holds for Android.
It lives in the Max Security level only (internal identifier `opsec`; Levels key `defense.ui`), the switch **Watch for
attacks** (Settings) is **off by default**, and hidden settings keep working like all others.

**Where it hooks in.** The userspace netstack (`internal/splitstack`) calls a narrow `Observer` (`observe.go`) from four
places: every DNS query (`relayDNS`), every DNS answer (`relayDNS` and `resolveOn`) and every new TCP/UDP flow that is not
blocked and not DNS (`handleTCP`, `handleUDP`). The hot path only puts a small item into a bounded channel (512) and
**drops it when the channel is full** (`Engine.ObserveDropped`, shown as `defense.dropped` in the status); one worker
goroutine does the rest, so a slow observer costs events, never throughput. Answers are copied (about 512 bytes) and parsed in
the worker. `mobile/defense.go` turns this into calls on `defense.Manager`, created without a listen function. The
Manager is configured with the features that work here and nothing else.

| Feature | On Android | Notes |
|---|---|---|
| `dns_tunnel` | yes | Fed from the netstack's DNS, keyed per app (a synthetic key from the UID, not an address of any network). |
| `beacon` | yes | New outgoing TCP flows per app and destination; NTP/DNS/DHCP ports exempt, like on Linux. Better than Linux: the UID comes from `getConnectionOwnerUid`, no cgroup guessing. The Shunt itself is outside its own VPN and never appears. |
| `first_seen` | yes | Same 10 minute learning phase and 6 notes per minute as on the PC. Memory in `files/defense/first-seen.json` (mode 0600, hashed targets). The app is the package name (`PackageManager.getPackagesForUid`, looked up in the worker, not in the packet path). |
| `reputation` | yes, report only | Feodo and SSLBL (`defense.reputation_sources` and `reputation_off` as on the PC). Go has no system resolver on Android, so Kotlin downloads the list files like the filter lists (by the app itself, outside its VPN, a copy older than 12 h is fetched again) into `files/defense/rep-<name>.txt` and the core loads them (`DefenseSources`, `DefenseReload`, expiry from the file age as on the PC). A hit is one `reputation` event (high) that names the app. |
| decoys, tarpit, cowrie, scan, brute (also `brute_service`) | no | Need listeners or the packet log; forced off. |
| `arp`, `dhcp`, `dhcp_option`, `rogue_ra`, `new_iface` | no | Need packet sockets or netlink, which apps may not use without root. The app says so. |
| `tls`, `dns_rebind` | not built | The TLS check would have to dial through the direct route and pin per network; left out. Rebind needs an answer hook that can drop; this one only watches. |
| `evil_twin` | not built, open | The BSSID needs `ACCESS_FINE_LOCATION` (and a location switch); no new permission is requested for it. A later version could ask in the user's own time. |

**Blocking.** The Block switches are ignored on Android (`mobile.DefenseConfig` clamps every feature to watch only): the
netstack has no deny list for destinations, and a false alarm that cuts a banking app is worse than a message. Open.

**Network class.** The class (unknown, unsafe, safe; not rated = unknown; the old trusted, public and managed are read as safe, unknown and safe) is stored per kind of network (`wifi`,
`mobile`) in `Store.kt` and passed with `DefenseNetwork(key, class)` on every network change. The key is a hash of the
kind (a Wi-Fi name is not read: that would need the location permission), and it is never logged or sent.

**Status and events.** `Status()` gets a `defense` object (`enabled`, `heat`, `level`, `class`, `exposed`, `last_seq`,
`dropped`, `sources`); `DefenseEvents(since)` returns the events as on the PC. The Status tab shows a thermometer and the
last events (German and English via `internal/i18n/lang/de.json`).

**Privacy.** Everything stays on the phone: events in memory (1000), first-contact memory hashed in the private app
directory, list files from public URLs. No SSID, BSSID, MAC or address of the user's own network goes into an event or a
log (private and link-local destinations are not tracked; only public destinations and package names appear). No new
permission and no `QUERY_ALL_PACKAGES`: the package name of a UID comes from `getPackagesForUid` (with package visibility
filtering on Android 11+ an app that is not visible shows as `uid-N`, which first-contact tracking skips). Known: the core's existing log line for a network change still prints the
Wi-Fi name that the app passes; the app passes an empty one today.

**Not tested here.** The Kotlin side was written but not built (no `shunt-core.aar` and no Android NDK on this
machine); the Go side has unit tests and runs under `go vet` with `GOOS=android`. Netstack hooks (hot path, concurrency)
need a review before release.

Evidence endpoints: `GET /v1/defense/evidence` (status, cases), `POST .../case` (`create|pin|unpin|delete`), `POST .../purge` (`all` also removes kept cases), `POST .../export`, `GET .../download?name=`, `GET .../abuse?src=` (all but the first need authorization).
