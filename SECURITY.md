# Security

The Shunt decides which traffic leaves through which tunnel. A bug can leak
traffic, so security reports are welcome and taken seriously.

## Reporting

Please use GitHub's **private vulnerability reporting** (Security → Report a
vulnerability) instead of a public issue, or write to
**shunt@isst.pizza**. We acknowledge a report within 7 days. Include what you
did, what leaked or broke, and the output of `shunt status --json` and
`journalctl -u shuntd` (remove anything private).

## What The Shunt protects against

- Traffic of a route leaving outside its tunnel: kill switch in the routing
  table, leak guard in nftables, fail-closed when the daemon is stopped or
  crashes, IPv6 blocked for tunnels without IPv6.
- DNS leaks: every port-53 query is answered by the resolver of its route;
  DoT is blocked, known DoH servers are refused.
- Hostile local networks pushing routes (TunnelVision, DHCP option 121):
  tunnel traffic is policy-routed and never consults the main table.
- Unprivileged local users: only members of the socket group may talk to
  the daemon; changing anything needs root or polkit (admin password).

## Known limits – read before relying on it

- **Per-app routing is not a sandbox.** A process in a tunnel route that
  wants out can ask other software to start something for it (for example
  `systemd-run --user`, D-Bus activation, a browser handing a link to
  another program). Shunt stops the obvious way (its own API needs the admin
  password to move a process out of its route), but not the whole desktop.
  If an application must never reach the internet except through the tunnel,
  route *everything* through the tunnel (`default_route = "tunnel:<name>"`)
  or run it as a separate user or in a VM.
- **Tor connects to its relays directly.** A Tor tunnel (and the Tor route
  `tor-all`) carries your traffic through Tor, but Tor's own connections to
  its relays or bridges leave over the normal network of the machine, not
  through another tunnel. The local network (Wi-Fi owner, provider) can see
  that you use Tor, though not what you do. To hide this, put the Tor tunnel
  behind a WireGuard tunnel with `via` (Linux only), or use a bridge
  (obfs4, snowflake, meek, webtunnel).
- **App rules are best effort**: a program is moved into its route right
  after it starts; a connection opened in the first milliseconds would keep
  the old route. On Linux with eBPF (kernel 6.1 or later) the start guard
  covers a program from its exec on, its threads and children included: its
  sockets get the rule's route (rules that name programs only, without
  arguments, ports or destinations, and only if no rule for all programs
  comes first), or are refused for a moment until the program is in its
  group (rules by path, arguments, ports, or after such a rule; a program
  may then see "operation not permitted" once). Flatpak rules keep the
  window. `shunt check` warns when the guard is not available. Menu entries
  made with `shunt desktop` and `shunt run` have no such window.
- **Domain rules trust DNS.** Whatever the route's resolver answers is
  routed. On foreign networks use an encrypted `dns.direct` (tls/https).
- **Apps with their own encrypted DNS** bypass domain rules (app, IP and
  port rules still apply).
- **OpenVPN configs run as root.** Shunt refuses everything in a `.ovpn` that
  starts programs, loads plugins, writes files or changes privileges, and
  imports over the API/UI only accept inline certificates. Still, openvpn
  itself is a large program parsing a file you got from someone: use configs
  from providers you trust.
- **Network profiles trust what the network says.** A Wi-Fi name can be
  faked by anyone; match on the router MAC too for profiles that relax
  protection. A MAC can be spoofed by someone on the same network.
- **Multi-hop endpoints given as host names** are resolved by shuntd directly
  (your local DNS learns the name of the inner server). Use an IP address in
  the inner config if that matters.
- **Desktops and browsers move programs into systemd scopes** of their own (COSMIC,
  Chromium). Shunt moves them back within about 0.1 s; a connection opened in that
  window keeps the default route (with the start guard: the rule's route, for
  rules by program name). For apps that must never touch the default route,
  make the default route a tunnel or use the app firewall in `block` mode.
- **Domain rules and explicitly started apps**: an app started in a tunnel keeps that
  tunnel for its traffic even when a (non-override) domain rule names another route, but
  its DNS lookup for that domain is still answered by the domain rule's resolver.
- **The app firewall holds programs of the desktop session only.** Its first packets
  are rejected (not delayed); programs that talk through an already running process
  (D-Bus services, browser handover) take that process's route. Desktop components
  (shell, audio, portals) are never asked about; that exception needs both the name and
  a program file in a system directory (`/usr`, `/opt`, …), so a program that only
  names itself like one is still asked about. It is a question for honest apps, not a
  sandbox: a program may still connect in the moment before it is held.
- **root on the machine** can do anything, including turning Shunt off.

## Android: tunnel keys at rest

The Android app stores each tunnel's secret part (the WireGuard file with its
private and preshared keys, OpenVPN keys and inline certificates, OpenVPN user
and password, Tor bridge lines) sealed with AES-256-GCM in `settings.json`
(`android/app/src/main/java/org/theshunt/app/Vault.kt`). The AES key is made in
the Android Keystore (StrongBox when the phone has one, otherwise the TEE) and
cannot be read out; a copy of the app's files holds only ciphertext. Tunnel
names, types, routes and the other settings stay readable, so the app can show
and fail closed without the key.

- **Migration:** a `settings.json` from an earlier version (keys in clear) is
  sealed on the first start: the new file replaces the old one atomically, then
  the old file's bytes are overwritten with zeros. If the key store fails, the
  old file is kept and the app runs on; it tries again on the next start.
  Flash storage may keep copies of old blocks (wear levelling) that no app can
  reach; only a factory reset clears those.
- **Key gone** (files moved to another phone, restored copy, key store reset):
  the tunnels show as *locked*. They are never handed to the VPN core and every
  route that names one of them (default, apps, network profiles, tunnels going
  through it, Tor for everything) blocks. Their sealed values are kept as they
  are. Delete the tunnel and import its file again.
- **Not bound to the screen lock:** the key works while the phone is locked,
  because the VPN must restart then (always-on, watchdog). Before the first
  unlock after a boot the app's files are not readable at all; the app then
  sees no tunnels and blocks everything. A sealing error never writes keys in
  clear: the change is not saved and the app says so.
- **Limits:** the key protects the files at rest, not a running phone. Root or
  an exploit in the app's process can use the key store key (or read the keys
  from memory, where the VPN core needs them in clear). Backups are off
  (`allowBackup="false"`, `dataExtractionRules` exclude everything).
- **Files for the helper programs:** openvpn and the built-in Tor read their
  setup from a file. The core writes it (0600, in the app's private
  `files/openvpn/<tunnel>/tunnel.ovpn` or `files/tor/<tunnel>/torrc`) just
  before the program starts and wipes it (overwrite with zeros, then delete;
  `internal/secfile`) as soon as the program has read it: openvpn when it
  connects to the management socket (it parses the whole file, inline keys
  included, before that, and never reads it again), Tor when its control
  port answers; also when the program ends or cannot start. The OpenVPN user
  and password never go into the file (management interface). Rests of a
  crash or kill in that moment are wiped at the next process start
  (`ShuntApp.kt`), before every engine start and after every stop
  (`splitstack.CleanWorkDir`, which also removes the `openvpn/` and `tor/`
  folders of deleted tunnels). Tor's data folder (`files/tor/<tunnel>/data`)
  stays on purpose: it holds Tor's guard and directory state, which Tor keeps
  so that it does not pick new entry nodes on every start; with bridges that
  state names the bridge in use (address and fingerprint, not the obfs4
  secret). It goes when the tunnel is deleted. The files stay in the app's
  folder rather than the cache folder: both are app-private and excluded from
  backups, and the cache folder could be cleared by Android while Tor runs.
  The Windows and Linux desktop paths are unchanged (they do not start this
  built-in Tor or openvpn).
- **Not yet tested on a device:** the instrumented test `VaultDeviceTest`
  (real Android Keystore: seal, open, migration of a clear `settings.json`,
  locked tunnel after the key is deleted) is built but has not run. It is to
  run on the desktop machine against a test phone or an emulator
  (`./gradlew connectedPlayDebugAndroidTest`, emulator with `-no-window`); it
  overwrites `settings.json`, so never on a phone in use.

## Loopback listeners taken by another program (Linux and Windows differ)

The Tor proxy ports (53000+, 52000+) and the SOCKS exits of tunnels
(`socks = "127.0.0.1:1080"`) listen on fixed loopback addresses that any
local user could bind first. Shunt never hands such an address over: the
listener is not started and the log says so loudly.

- **Linux:** shuntd also drops all TCP to a taken address in its own nft
  table `shunt_torguard` (fail closed); programs set up for it get no
  connection instead of talking to the other program. A free address is
  bound on the next reload and lifts the block. If the block cannot be set,
  the reload fails.
- **Windows:** a taken SOCKS exit address is only refused and logged; there
  is no firewall block yet, so a program set up for that exit reaches the
  other program. On a machine shared with other users, check the service
  log for "SOCKS EXIT ADDRESS TAKEN" before relying on a SOCKS exit.
- **While shuntd is not running** nothing guards these addresses.

## Fixed findings of the external report on 755f910

- **M-02** (client caches an answer longer than the address stays in the
  domain set, then its traffic takes the default route): capped on Linux
  (c008c2e) and in the Android/Windows core (a2ef83b): an app never gets a
  TTL over the entry life minus grace (2 h − 30 s).
- **M-04** (proxy ports can be taken by local users): Tor proxy ports
  (cea8f86) and SOCKS exits (44ee55d), see the section above.
- **L-02** (a program could send queries to a route's DNS proxy listener
  directly): only redirected queries and shuntd's own reach them (786c26d).

## Verifying downloads

Release tarballs come with `SHA256SUMS` (checked by the installer) and a
build provenance attestation (sigstore). With the GitHub CLI:

    gh attestation verify shunt_linux_amd64.tar.gz --repo Bob-Nixkoenner/The_Shunt

This proves the file was built by this repository's release workflow.
