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
  sandbox: a program may still connect in the moment before it is held. This
  start race stays (external report M-01): holding every new program until the
  watcher has decided would need an eBPF hold for all programs started outside
  shuntd (system services included), which could refuse their sockets for up to
  2 s after every start. For apps that must never touch the default route, make
  the default route a tunnel.
- **`dns.direct = "system"` bypasses systemd-resolved** (external report L-13):
  shuntd asks resolved's upstreams itself in plain UDP (the stub on 127.0.0.53
  would loop back into the proxy), so DNS-over-TLS and DNSSEC set in resolved do
  not apply to direct queries; shuntd logs a warning when they are on. Set
  `dns.direct` to a DoT or DoH upstream to keep them encrypted.
- **Boot lockdown unit** (external report M-10): `shunt-lockdown.service` runs
  before `network-pre.target` but does not make it fail: if `shuntd lockdown`
  itself fails (nft missing or broken), the network starts unlocked. Making it a
  hard requirement would not stop NetworkManager (it only orders after
  `network-pre.target`), and binding it to NetworkManager could leave the
  machine offline with no way back but a console; an unreadable config does not
  lock on purpose for the same reason.
- **Windows, caller check of the local API** (external report L-09): AF_UNIX on
  Windows tells no connect time, so the caller's process creation time cannot
  rule out a process ID reused between connect and accept; the open handle pins
  the process only from the accept on. The window is milliseconds and an
  attacker cannot choose which process gets the ID. Closing it needs a named
  pipe with client impersonation, a larger change; not fixed.
- **Android, connections whose owner stays unknown.** The app learns which
  app opened a connection from Android (`getConnectionOwnerUid`). A miss is
  asked again twice, about 20 ms apart; if the owner is still unknown, the
  connection gets the default route in Simple and Pro (rest window: an app
  with a tunnel rule can then go out direct when the default is direct). Max
  Security drops such connections instead (the app tries again). Misses are
  logged as counts only.
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
- **Windows:** a WFP exit guard in its own sublayer lets only the service
  accept on its SOCKS exit addresses and only tor.exe on its SOCKS port, both
  running as the service's account; an exit address another program holds
  cannot be reached at all. The guard is not persistent: a crash leaves it in
  place until the service starts again, a clean stop or a reboot lifts it.
  Tor's control port is not guarded (a program holding it can only fake the
  bootstrap; the SOCKS port stays guarded), and apps using the loopback fast
  path (`SIO_LOOPBACK_FAST_PATH`) may pass WFP. Its runtime behaviour has not
  yet been verified on real Windows.
- **`shunt socks`** shows an exit whose address another program holds as
  BLOCKED.
- **While shuntd is not running (Linux):** on a clean stop shuntd leaves the
  guard table with all its loopback ports closed (DNS listener ports
  rejected, Tor proxy ports and SOCKS exits dropped); at boot `shuntd
  lockdown` closes the configured SOCKS exits until shuntd has bound them.
  After a crash only the last running guard stays (taken addresses) until
  systemd restarts shuntd (2 s). `shuntd cleanup` removes the guard.
- **Who may use a SOCKS exit (Linux):** every local program by default (that
  is what the exits are for), except programs the app firewall holds and
  programs whose rule blocks them. `socks_users = [...]` on a tunnel limits
  its exit to those users. Windows does not restrict who may use an exit.

## Fixed findings of the external report on 755f910

All 27 findings were checked against the code. 25 have a change in the code
(for L-13 a warning, for M-01 without the start race); M-10 and L-09 are not
fixed and listed under known limits above with the reason. The CHANGELOG
names the tests.

- **H-01** `.ovpn` check passed with a byte order mark or a close tag with
  text after it: files are read the way openvpn reads them.
- **H-02** install.sh took the current directory as its source: only a
  checkout owned by root or the sudo user, not writable by others.
- **H-03** start guard gave an `exe:` rule's open route by program name:
  never by name now, the watcher checks the path.
- **H-04** Windows data folder could be made by a user first: made with a
  protected DACL, a foreign-owned folder is moved aside.
- **M-01** never-ask exception by process name alone: needs a program file
  in a system directory too; the start race stays (known limits).
- **M-02** client cached an answer longer than the domain set entry: TTL
  capped to entry life minus grace (2 h − 30 s) on Linux, Android and Windows.
- **M-03** login page exception let any socket group move to the direct
  route: only the login browser's group.
- **M-04** Tor proxy ports and SOCKS exits could be taken by local users:
  blocked on Linux (nft), WFP exit guard on Windows, see the section above.
- **M-05** dhcphost took NetworkManager-like D-Bus signals from anyone: only
  from NetworkManager's current bus name.
- **M-06** SOCKS exits without local authentication: a UDP association
  belongs to one sender; on Linux held and blocked programs are rejected for
  TCP, optional `socks_users`.
- **M-07** Windows kill switch let the service and tor past by path alone:
  also requires the SYSTEM account.
- **M-08** Windows update could be swapped between check and start: locked
  and hashed again through the same handle.
- **M-09** F-Droid repo build could leave the keystore in the output: built
  in a private work folder, the output gets only `repo/` and `metadata/`.
- **L-01** installer fallback to an unchecked release installer: removed,
  the installer stops instead.
- **L-02** a program could query a route's DNS proxy listener directly: only
  redirected queries and shuntd's own reach it.
- **L-03** upstream answers not matched to the question: checked, random ID
  upstream.
- **L-04** login browser's DNS port took unmarked TCP queries unfiltered:
  now filtered.
- **L-05** no limit on names per DNS list: 20 million, cut loudly beyond.
- **L-06** malformed `PROGRESS=` line from Tor's control port crashed the
  app: ignored.
- **L-07** Windows kill switch reset a stricter firewall policy: kept,
  reset only to clean up the old kill switch.
- **L-08** Windows: two programs on one address and port picked by chance:
  owner unknown, default route.
- **L-10** Android (github flavor) update receiver open to other apps on
  Android 10–12: random action, own session only.
- **L-11** built binary and `ui.pid` in the repository: removed and
  ignored.
- **L-12** Debian postinst disabled a tor the admin had set up: only a tor
  that came with the package.
- **L-13** `dns.direct = "system"` bypasses resolved's DoT/DNSSEC: kept,
  warned about in the log (known limits).

## Verifying downloads

Release tarballs come with `SHA256SUMS` (checked by the installer) and a
build provenance attestation (sigstore). With the GitHub CLI:

    gh attestation verify shunt_linux_amd64.tar.gz --repo Bob-Nixkoenner/The_Shunt

This proves the file was built by this repository's release workflow.
