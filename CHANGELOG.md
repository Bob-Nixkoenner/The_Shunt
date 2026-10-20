# Changelog

## Unreleased

- Android: tunnels on demand (Tunnels tab, "Battery", on by default). A WireGuard tunnel no app uses is closed after 3 minutes (no keepalives, no radio wakeups) and made again on the first connection of an app on its route; the tunnel card shows "asleep". Tunnels an OpenVPN tunnel runs through (multi-hop) stay up. Turning it off wakes everything. Desktop: not yet.
- Android: DNS servers (Tunnels tab). A query to the tunnel's DNS that gets no answer within 2 s is asked of the next server; the one that answered is asked first for 5 minutes. Default list 1.1.1.1 and 8.8.8.8, own servers can be added and removed; "Ignore the DNS of the tunnels" uses only that list (Tailscale's resolver stays). The tunnel health probe tries the same list, so a dead DNS line in a config no longer marks the tunnel as down.

## v0.7.1-rc5

- DNS: `dns.fallback = "<upstream name>"` adds a second server (e.g. 8.8.8.8) to every route whose servers are public addresses; private resolvers are never replaced. A UDP query without an answer is sent once more after 1.5 s (one lost packet no longer costs the whole 4 s timeout).
- Tray: "DNS for … does not work" is only shown after the failure lasted a minute (a lossy tunnel made it flicker for seconds at a time); the window still shows it at once.

## v0.7.1-rc4

- Linux: "Install update" shows the reason when the installer cannot start (no polkit agent, password prompt cancelled) instead of staying on "Working…". Tested in the Ubuntu VM: v0.7.0 to v0.7.1-rc3 with the button.
- Windows: the update check and the "Install update" button are on (they were switched off in the app on Windows).
- UI: the button stays on "Installing…" until the update is done.

## v0.7.1-rc3

- Android: the APK is signed with a fixed key (CI secrets `SHUNT_KEYSTORE_B64`, `SHUNT_KEYSTORE_PASSWORD`) instead of a random debug key per build, so a new version installs over the old one. Builds before rc3 have other keys: uninstall once (and remove the old entry under Settings > VPN).
- Android: importing a config from a cloud provider (e.g. Nextcloud) crashed with `NetworkOnMainThreadException`; the file is now read off the main thread and read errors are shown instead of crashing.
- Android: "Update" section on the status screen: press Check, then Download and install. Only asks GitHub on that press. The APK is installed only if SHA256SUMS carries the release key's signature (verified in the Go core, `internal/update/verify.go`) and the APK matches its hash. Needs "Install unknown apps" once; Android asks to confirm each update.
- Linux/Windows: "Install update" button in the update bar (instead of only a command). Linux: runs the installer after a polkit password prompt (log: `~/.config/the-shunt/update.log`); Windows: downloads the setup, checks the signed checksum list and the file's hash, starts it with the UAC prompt. Source builds keep the command.

## v0.7.1-rc2

- Windows: own window (WebView2) instead of an Edge app window, fixed UI port 47615, tray icon clicks and menu work (the tray's message loop was missing), "Restart service and app" keeps the app, setup option "Start the tray at login" (on by default), https links open in the default browser.
- DNS filter: defaults per OS (Windows telemetry lists in `normal` on Windows only; no phone/TV lists), lists are stored once in the lowest level and deduplicated by URL, "Tidy lists" button, local lists (`file:/path/to/list.txt`).
- Launchers: Chromium family (Chrome, Chromium, Brave, Vivaldi, Opera, Opera GX, Edge): existing profiles are found and get a launcher each (own data folder in `~/ShuntProfiles` that links to the profile), new profiles get their own folder.
- Snap browsers that refuse a pre-placed cgroup (Brave, Vivaldi, Opera GX: "is not a snap cgroup") now start: `shunt run` starts them as they are and shuntd moves them into the route as soon as they have become the app (`POST /v1/adopt`, own processes only, only ones in no route yet).
- Rules: hint when an address/domain/port rule does not reach apps started in a route, one click to change.
- UI: folded sections, theme and graph range are kept in the user's config folder (`shunt/ui-state.json`) as well, so they survive a restart even when the page address changes.
- UI: no longer breaks while no tunnel exists. Test builds (`-next`, `-wgui…`) never show an update warning.
- DNS: a UDP query that the (per conntrack entry) nat redirect sent to another route's listener is answered for the route its packet was marked for (`SO_RCVMARK`, Linux 6.1+; older kernels keep the old behaviour). The mark is no longer overwritten on loopback (`mark_in`). Found and tested with two programs using the same source port within 30 s.
- Release: Debian packages `the-shunt` (amd64, arm64) and `the-shunt-desktop` (amd64), CycloneDX SBOM.

## v0.7.1-rc1

**Pre-release: new overview with traffic and block graphs, an Apps tab, the DNS filter on Windows, and
Android updates.** Tested on Linux (Ubuntu VM), Android (emulator) and Windows 11 (VM); not yet on a
real Windows laptop.

- **Android: "Disguise on foreign Wi-Fi" removed.** An app cannot set the MAC address, and the device
  name only with `adb shell pm grant … WRITE_SECURE_SETTINGS`, which no normal user does; the name is
  not what the DHCP host name is made from on current Android either. The permission is gone from
  the manifest. For foreign Wi-Fi use the system's own settings (per network: *Privacy → Use
  randomized MAC*).
- **Light/dark switch in the web UI** (Configure → General → Appearance: follow the system / light /
  dark), kept per browser.
- **Fewer DNS filter lists:** the LG TV and Samsung lists are no longer offered or in the defaults,
  Windows' telemetry lists only on Windows. Lists that are in your config stay and show up under
  "Other" so you can remove them.
- **Android: rename tunnels** (Tunnels → Rename, with the VPN off): routes of apps, the default
  route, tunnels going through it and the traffic counts follow the new name.
- **Android: dark mode switch** (Status → Appearance: System / Light / Dark).
- **Android: DNS filter lists as on the desktop**: 26 RPiList lists in groups with their size, big
  lists (15 MB and more) are asked about before they are switched on. Windows and Office telemetry
  and TV lists are not offered on the phone.
- **Android: traffic and blocks graph** on the status screen (1 h / 24 h / 7 d / 30 d), blocked
  today / this month, and a history line on every tunnel card.
- **UI: new "Apps" tab** with Menu apps (Programs on Windows), "Start an app" and "Where traffic
  goes". Launchers show up there only when Firefox is installed (or launchers exist already).
  Each menu app has its own **DNS filter level** (off/low/normal/paranoid), stored as a rule
  without a route. The tab is remembered in the address (`#apps`).
- **Overview: traffic and blocks.** Graph of tunnel traffic (down/up) and DNS blocks with a
  1 h / 24 h / 7 d / 30 d switch, tiles for "blocked today / this month", and a small history
  line on every tunnel card. The daemon keeps 5-minute counters for 35 days next to the traffic
  totals (`GET /v1/history`); direct traffic is not measured. Linux first.
- **Leak test** runs by itself a few seconds after a tunnel comes up or goes down (switch in the
  card, on by default); the last verdict is shown as a pill in the header.
- **Rules** on the overview show the first four, the rest is under Configure.
- **Windows: the DNS filter works** (before, the lists were saved but ignored and the status showed
  nothing). The service downloads the lists of `[dns_filter] default` and answers blocked names
  with NXDOMAIN; the DNS filter tab shows lists, counters and the last blocked names. Levels per
  rule, tunnel or network are still Linux/Android only (the service warns).

## v0.7.0

**The first release after the release candidates: Linux, Android and Windows (beta).** Same
code as v0.7.0-rc11; the details of each step are in the rc sections below.

- **Tunnels:** WireGuard, OpenVPN (also as second hop), Tailscale/Headscale; rename with
  `shunt rename`; one "Add a tunnel" tile in the UI.
- **Routing:** per app, per rule (domain, CIDR, port), per network (Wi-Fi name, cable, mobile
  data), app firewall, sticky routes, panic button, timed pass, kill switch.
- **DNS filter:** blocklists inside The Shunt (RPiList lists, AdGuard/Pi-hole/hosts formats),
  pasted as whole blocks, grouped like the RPiList page, allowlists, three levels that build on
  each other, per app, tunnel and network.
- **Platforms:** Linux (installer for Debian/Ubuntu, Arch, Fedora; signed releases), Android
  app (APK), Windows (setup.exe and ZIP, beta).
- **UI:** foldable tiles, long lists scroll, health, statistics, leak test.

## v0.7.0-rc11

**Installer fix.** GitHub lists releases as text ("rc9" before "rc10"), so the installer took
the wrong one as "newest", called it outdated and built from source. It now looks through the
recent releases for the one that is exactly the current code. Nothing else changed since rc10.

## v0.7.0-rc10

**DNS filter: lists grouped like on the RPiList page** (ads, malware, phishing and scam, fake
shops, domain squatting, tracking, youth protection, other; your own URLs sit under "Other"),
and more lists in the defaults: low = easylist, normal adds Phishing-Angriffe and malware,
paranoid adds crypto, spam.mails, notserious, Fake-Science, the telemetry lists and
SupportingRussia. Everything else of rc9 is unchanged; the repository's default branch is now
`main`, so the installer from the README installs the release.

## v0.7.0-rc9

**UI: foldable tiles, one "Add a tunnel" tile; DNS filter: list blocks, allowlists, levels
that build on each other; `shunt rename`.**

**Foldable tiles, long lists scroll.** Tiles on Overview, Configure (tunnels, networks)
and DNS filter fold with a click on the heading (remembered per browser). Leak test, rules,
DNS, menu apps, statistics and recently blocked show at most 5 rows (lists per level: 10),
the rest scrolls. Firefox profiles in Launchers are folded by default. "Start an app" and
"Where traffic goes" moved to the bottom of Overview. WireGuard/OpenVPN and
Tailscale/Headscale are one "Add a tunnel" tile with two tabs.

**Update check per release type.** Settings: ask GitHub for releases, pre-releases (rc), both
or neither (neither = no requests).

**DNS filter: levels build on each other.** A list in `low` is also in `normal` and
`paranoid`, a list in `normal` also in `paranoid` (the daemon merges the levels, the UI ticks
the higher boxes for you and unticking clears the lower ones).

**DNS filter: paste whole list blocks, allowlists.** The UI takes a block of URLs at once
(one per line; Pi-hole adlist exports and the RPiList copy block work, comments and
non-https lines are skipped, duplicates removed) and puts them into a chosen level.
AdGuard Home lists were already understood (`||name^`). New `dns_filter.allow_lists`:
lists of names that are never blocked (hosts, plain names, `||name^`, `@@||name^`),
downloaded and refreshed like blocklists.

**Rename tunnels.** `shunt rename OLD NEW` (API: `POST /v1/tunnels/{name}/rename`)
renames a tunnel: its files, the default route, networks, rules, second hops and stored
app-firewall answers follow; the user's menu launchers are re-pointed by the CLI. The
tunnel restarts under the new interface name.

## v0.7.0-rc8

**Same content as rc7 (Tailscale/Headscale tunnels, launcher start button), now with the
Windows ZIP and `setup.exe` again.** The release pipeline builds the Windows files only while
the repository variable `BUILD_WINDOWS` is `true` (a switch to leave them out of a release).

## v0.7.0-rc7

**Tailscale / Headscale tunnels on Linux and Windows, a start button for launchers.**

- **Tailscale/Headscale tunnels (new).** A tunnel file `NAME.ts` (`login_server`,
  `auth_key`, `hostname`, optional `exit_node`) next to the WireGuard and OpenVPN files,
  `driver = "tailscale"`. Without an exit node only the tailnet (100.64.0.0/10) is
  reachable, with one everything routed into the tunnel leaves through that node (IPv4
  only). Import the `.ts` file in the window like any other config.
  - **Linux:** Shunt starts its own `tailscaled` in a private network namespace (tailscaled
    and `tailscale` must be installed), so its routes and rules never touch the host. Kill
    switch, panic and "this machine is no router" hold like for the other tunnels.
    Integration test: `test/integration/tailscale.sh` (needs headscale).
  - **Windows:** Tailscale's own userspace client (tsnet) runs inside the service: no
    adapter, no routes. Traffic outside the tailnet is refused unless the exit node is
    online, so nothing can leave through the normal network by accident.
  - Not on Android yet. The Windows build now needs Go 1.26.4 (tailscale.com v1.100.0).
- **Launchers: start button and route check.** Every launcher in the window has a "Start"
  button and shows whether the program runs, and with which route. If it already runs with
  another route (started from the normal menu entry, or as default browser), you are
  warned before a second start, which would usually join that copy and keep its route.

## v0.7.0-rc6

**Windows (beta) joins Linux and Android; the release pipeline now builds the APK and the
Windows ZIP.**

- **Windows (new): service, window and installer.** `shuntd-win` runs as a Windows
  service (wintun adapter + the Android/WireGuard core) and serves the same `/v1` API as
  the Linux daemon over a Unix socket, so the CLI-style API and the web UI work
  unchanged. It reads the same `shunt.toml` (in `C:\ProgramData\Shunt`; the window edits
  it, with checks, backup and live rule changes). Per-program routes match the program's
  file name (`app = ["firefox"]`) or path (`exe:C:\\Tools\\x.exe`), plus rules by address,
  port and domain, panic, pass, leak test and traffic statistics. `shunt-desktop.exe`
  gives a tray icon, toast notifications, autostart and a window (Edge in app mode).
  Optional **kill switch** (`[daemon] kill_switch = true`): Windows Firewall blocks
  everything that bypasses The Shunt, also while the service is down after a crash.
  Install with `packaging/windows` (`build.sh` makes the ZIP, `install.ps1` installs).
  `link:wifi|ethernet|mobile` routes work there too. Not yet on Windows: OpenVPN, groups,
  DNS filter, app firewall.
- **Release assets**: the pipeline builds the Android APK (`shunt-<tag>-android.apk`, debug
  signed) and the Windows installer ZIP (`the-shunt-windows-amd64.zip`) next to the Linux
  tarballs; both are in the signed `SHA256SUMS`.

## v0.7.0-rc5

**Android: OpenVPN tunnels, multi-hop and disguise on foreign Wi-Fi – plus fixes from the
VM tests (Ubuntu 26.04, CachyOS).**

- **Android: OpenVPN tunnels** next to WireGuard (import a `.ovpn` file or a QR code);
  OpenVPN runs behind the app's own TUN, per app like every other tunnel.
- **Android: `via` (multi-hop)**: an OpenVPN tunnel can run through a WireGuard tunnel.
- **Android: disguise on foreign Wi-Fi** (random device name).
- **Stopping shuntd keeps direct traffic working, DNS included.** Tunnels and the
  login browser stay blocked (their DNS too, fails closed), but direct programs now
  resolve names through the system resolver while shuntd is down. Before, every name
  lookup failed and the whole Internet looked gone.
- **Installer: restart instead of logging out** after being added to the `shunt` group;
  on KDE (and other desktops whose user services keep running) logging out was not
  enough. The hint only appears when the user is new in the group.
- **No DNS warning for Wi-Fi or mobile data that isn't there** (`link:wifi`,
  `link:mobile` without a connection or without the hardware).
- **Android app looks like the desktop UI**: same colours (dark and light), header with
  state and PANIC, sections, tunnel cards, route colours, leak test on the page, own
  "Filter" tab whose list names open their source and show how many names they hold.
- **Android: steadier VPN** (ideas from Rethink DNS): Android is told which real network
  carries the VPN (apps see Wi-Fi vs. mobile data), network changes are settled for a
  second before WireGuard reconnects, a status notification (foreground service, with
  Panic and Stop) keeps Android from ending the VPN, and a warning shows when Android's
  "Private DNS" is on (it bypasses the VPN's DNS and the filter).
- **`shunt remove NAME`** deletes a tunnel and its imported files (refused while the
  default route, a rule or another tunnel's `via` uses it).

## v0.7.0-rc4

**Installer for Arch and Fedora, tunnel health, traffic statistics, panic button and
timed pass – and the first Android app (preview).**

Installing: run the steps one by one (see README); to test a branch use
`sudo SHUNT_REF=<branch> bash install.sh --from-source`.

- **Tunnel health**: every tunnel is judged from handshake age, byte counters and a DNS
  probe through the tunnel (latency). `shunt status` shows e.g. `up/kernel ok 23ms`, the
  web UI state, latency and loss per tunnel. A tunnel without answers is re-resolved
  (DDNS) and re-created right away. Probes only run for tunnels in use.
- **Traffic statistics** per tunnel and for all together: this month, last month, total.
  Only sums, no connection records (`/var/lib/shunt/stats.json`, written at most every
  5 minutes). `shunt status` prints a TRAFFIC table, the web UI shows it per tunnel.
- **Panic button and a timed pass**: `shunt pass 1-60|off` lets everything go direct –
  past tunnels, blocks and the DNS filter – for at most an hour and ends by itself; the
  web UI shows a countdown and a red "PASS – unprotected" state. Needs the admin
  password, like lifting panic. Panic always wins.
- **Android app (preview, debug build, not in this release's files)**: one VPN, several
  WireGuard tunnels at the same time, a route per app (direct, block or a tunnel), DNS
  per route, DNS filter, tunnel health, traffic, panic tile, timed pass, leak test, and a
  warning when Android's own kill switch (always-on + block without VPN) is off. The core
  also does destination rules (domain, CIDR, port; names resolved over the rule's route)
  and network profiles (Wi-Fi name or mobile data → default route); the app screens for
  them follow. Details: `docs/ANDROID.md`.
- **Windows prototype** `shunt-win-proto` (wintun, route per program): builds, never run
  on Windows yet – `docs/WINDOWS.md`.
- **Tests**: `test/farm.sh` runs every CI check spread over machines reachable by SSH;
  the integration test no longer depends on being started from a terminal.

**Installer: Arch and Fedora, signed releases, dry run, full log.**

- **Arch Linux** (Manjaro, EndeavourOS) **and Fedora**: the installer uses pacman or dnf
  instead of apt (same packages, distribution names). pacman runs without `-Sy` (no
  partial upgrade); if the package database is too old it says to run `pacman -Syu`.
- **Signed releases**: the release workflow signs `SHA256SUMS` (`ssh-keygen -Y sign`,
  secret `SHUNT_RELEASE_KEY`, checked against the installer's key before publishing).
  The installer only installs a release whose signature is valid; unsigned releases
  (all up to v0.7.0-rc3) are built from source instead. A wrong signature stops the
  installation.
- **`--dry-run`**: checks the system and network and lists what would be installed
  (packages, release or source build, config, nsswitch, NetworkManager, service) –
  changes nothing, works without root.
- **CI checks the package names** of all three package managers (`installer-packages`:
  Arch, Fedora, Debian containers, `test/installer/packages.sh`).
- **Full log** `/var/log/shunt-install.log`: every message, question and answer, plus the
  output of every step; kept across runs (rotated at 1 MiB), ends with the exit code.

## v0.7.0-rc3

**DNS filter: blocklists inside The Shunt, like Pi-hole – per app, tunnel and network.**

- **New tab „DNS filter“**: blocked names get NXDOMAIN right in Shunt's DNS proxy and never
  reach any DNS server – handy when your own Pi-hole/AdGuard is out of reach and you have
  to go through 1.1.1.1.
- **Three levels** `low`, `normal`, `paranoid`, each with its own lists (tick boxes in the
  UI). Default: everything on `normal` = EasyList; `paranoid` adds phishing, malware,
  telemetry and crypto lists.
- **Which level applies** (most specific first): a rule for the app or group
  (`dns_filter` on a `[[rule]]`, also without route: Firefox `low`, Brave `paranoid`) →
  the tunnel (`dns_filter` on `[tunnel.x]`) → the network you are in, for direct and
  Wi-Fi/cable routes (`dns_filter` on `[[network]]`) → `dns_filter.default`.
- **Lists only load when needed**: only lists of levels that are used somewhere are
  downloaded (through the default route, resolved by Shunt itself), cached in
  `/var/cache/shunt/blocklists` and refreshed daily. Not used = not downloaded, not in
  memory. EasyList costs about 11 MB RAM, 0.4 µs per query.
- Allowlist („Never block“), „Recently blocked“ with an Allow button, counters, “Update
  lists now”; `shunt status` shows the lists.
- Names routed on purpose with a domain rule and the Wi-Fi login browser are never filtered.
- Lists: [RPiList/specials](https://github.com/RPiList/specials/tree/master/Blocklisten) –
  thank you to the RPiList project. Own lists: any https URL (hosts, domain list or
  `||name^`).
- **Fix: no false “Update available”** for source builds that are newer than GitHub's
  newest commit (local commits, or a branch ahead of it). The check now asks GitHub how
  the build relates to the newest commit; only “behind” (or diverged) is an update.
- The systemd unit gets `CacheDirectory=shunt` (update with the installer); older units
  keep the lists in `/etc/shunt/blocklists`.

## v0.7.0-rc2

**Wi-Fi vs. cable, DNS per network, Firefox profiles everywhere, and security fixes from
a code review.**

- **Leak test without password**: the daemon starts the probes right inside each route
  (before, the CLI/UI moved them there and, with a tunnel as default route, every route
  asked for the password). Wi-Fi/cable routes are judged by their own rules (same IP as
  direct is expected, not a leak).
- **App firewall**: the block rule of a held program that ended without going online is
  removed with it; holding and releasing are logged.
- **Under the hood – ready for other platforms**: the daemon talks to the operating system
  only through one interface (`daemon.Backend`, Linux: cgroups/nftables/netlink).
  Everything but the Linux tray builds for Windows and macOS, checked in CI – the base for
  Windows and Android versions.

- **New: routes per connection** – `link:wifi`, `link:ethernet`, `link:mobile`. With Wi-Fi
  and cable plugged in, one program can go over the Wi-Fi and another over the cable
  (rules, `shunt run --via link:wifi`, firewall answers, and `via = "link:wifi"` for a
  tunnel). Not connected → its traffic is blocked, it never takes the other connection.
  DNS goes to the server that connection got (or `dns.direct`). Interfaces are found
  automatically and followed when they change.
- **Fix: a fresh tunnel table got its routes before the kill switch route**; misses could
  fall through to the main table for a moment. One failing route no longer keeps the
  others out.
- **Wi-Fi login pages with your own DNS**: the login browser (`shunt captive`, tray) now
  resolves through the Wi-Fi's own DNS server instead of `dns.direct` – guest Wi-Fis often
  block other DNS servers until you log in, or use names only they know. Only that
  browser; everything else keeps its DNS. While a login page is detected it needs no
  password, otherwise it does (it leaves the default route).
- **Fix: saving the config failed right after plugging in a cable** ("table 5525 route
  0.0.0.0/0: network is unreachable"). Copying the Wi-Fi/cable/LAN routes into Shunt's
  tables fails while an interface is still coming up; that failed the whole reload.
  Those routes are retried every 5 s now (the table blocks meanwhile, nothing leaks).
- **Fix: stalling TLS handshakes and downloads through some tunnels** (MSS clamping).
  Programs announce their TCP segment size for the physical connection (1460) before
  Shunt moves them into a tunnel (MTU 1420). Servers then sent packets too big for the
  tunnel; where the "fragmentation needed" reply gets lost, connections hung – small
  things like ping worked. TCP connections into a tunnel now announce what fits.
- **Fix: UDP inherited the route of an earlier flow with the same ports.** A program
  sending from a source port another program's UDP flow just used (same destination)
  took that flow's route – seen as a sporadic "LEAK" of the block route in the leak
  test, and usable to leave a tunnel or block. Only TCP keeps its connection's route
  now; UDP is classified by its program on every packet.
- **Firefox profiles found wherever Firefox keeps them**: newer Firefox (`~/.config/mozilla`),
  deb/ESR (`~/.mozilla`), Ubuntu's snap, flatpak, Windows (`%APPDATA%`) and macOS – and the
  profiles of Firefox's newer profile manager, whose names are only in its database
  (read with a small built-in reader, no SQLite library). Profile launchers now start
  the profile by folder (`--profile`), so they work for those profiles too.
- **Switch tunnels off without deleting them**: `disabled = true` (Configure → Tunnels →
  “switched on”). Files, password and rules stay; the tunnel is not connected and its
  apps are blocked (never sent another way). The tray doesn't warn about it.
- **DNS per network profile**: `dns_direct` in a `[[network]]` (Configure → Networks →
  “DNS direct”): e.g. the Pi-hole at home, 1.1.1.1 on a guest Wi-Fi, or `"system"` for
  the network's own DNS server. Applies to `direct` and the Wi-Fi/cable routes.
- **Fix: `allow_lan` skipped the LAN of the cable/Wi-Fi interfaces** once link routes
  existed (they were taken for tunnel interfaces).

- **Fix: held and default-route programs could move themselves to `direct`.** A program
  held by the app firewall, or running on a tunnel default route, could ask the daemon to
  start it in another route without the password. Now that counts as leaving a route:
  with a tunnel as default route, `shunt run --via direct …` asks for the password.
- **Fix: a blocked program could forget its own block** (`shunt firewall forget`) without
  the password; now the same rule as for answering applies.
- **Fix: held programs had network for a moment on every reload** (and for good if the
  reload failed halfway); their rules now come with the new ruleset in one transaction.
- **Fix: a network profile switch that failed was never retried** – the previous
  profile's default route stayed (e.g. `direct` from home on a café Wi-Fi). Retried every
  5 s now.
- **Fix: after editing rules, addresses of an old domain rule could land in another
  rule** (up to 2 h, until they expired). They are only kept when the rule's domains are
  unchanged.

## v0.7.0-rc1

**App firewall, sticky routes, rule priorities and rules per network.**

- **Rule order changed – nothing overrides “block”**: programs started in the block route
  come first, then rules marked `override_explicit = true`, then programs started in a
  route on purpose (`shunt run --via`, menu entries, firewall answers), then all other
  rules, then the default route. Before, a rule like `192.168.1.0/24 → direct` let even
  `shunt run --via block` into the LAN and took tunnelled apps past their tunnel.
  **Check your rules**: a rule that should also apply to apps started in a tunnel needs
  `override_explicit = true` (checkbox “also for apps started in a route”).
- **Rules per network profile**: `network = ["home"]` on a rule (checkboxes in the rule
  editor) – a home-LAN rule no longer matches a foreign Wi-Fi with the same addresses.
  Applied again on every network change.
- **Sticky routes survive a restart of the service**: processes already in Shunt groups
  are adopted again.
- **Update banner** no longer says “update available” after an update when only the app
  was not restarted; it says so instead (“this window still runs …”).
- **App firewall** (`[firewall] mode = "ask"` or Configure → App firewall, presets
  Paranoid / Normal / Off, per network profile): a program of your desktop session
  without a rule is held when it first goes online – nothing gets out – and the window
  asks which way it may go (tunnel, direct, block; remembered by default). No answer
  within 30 s → default route (`ask`), or blocked until you decide (`block`). Terminal
  programs take the terminal's route unless `ask_terminal = true`; system services are
  never held. CLI: `shunt pending`, `shunt allow`, `shunt firewall apps|forget`.
- **Fix: Brave/Chrome left their route under COSMIC.** The desktop moves started apps
  into systemd scopes of their own, and Chromium-based browsers move themselves once
  more – out of Shunt's group, onto the default route. Shunt now remembers every
  process it placed (with its children) and moves it back within 0.1 s.
- **Wi-Fi login pages are detected**: after every network change shuntd checks for a
  captive portal (hotel, train, company guest Wi-Fi). The tray turns yellow, a
  notification comes, and the window asks whether to open the login page in a
  throwaway browser that goes past the tunnels. When you are logged in, the tunnels
  connect by themselves. `shunt status` says so too. Off with
  `[daemon] captive_check = false` (the check asks nmcheck.gnome.org over plain HTTP).
- **Provider .ovpn files import as they are**: DNS scripts and other lines Shunt does not
  run (`script-security`, `up`, `down`, plugins …) are commented out with a note instead
  of refusing the file; Windows-only options (`block-outside-dns`, …) no longer stop
  openvpn on Linux.
- **Installer** checks the connection to GitHub first (20 s) instead of hanging silently;
  with The Shunt active it offers to run itself past the tunnels.
- **Local network past the tunnel** (`allow_lan = true` per tunnel, checkbox in Configure):
  apps in that tunnel still reach printer, NAS and router of the network you are in;
  only directly attached private networks, everything else stays in the tunnel.
- Leak test easier to read (one card per route, long IPv6 resolvers wrap).

## v0.6.0

**OpenVPN, multi-hop, network profiles – and the fixes from the first real-world test.**

### New
- **OpenVPN tunnels** (`driver = "openvpn"`): import a `.ovpn` in the app or with
  `shunt import file.ovpn`; username/password are stored in a 0600 file. Shunt runs
  openvpn itself without scripts; anything in a `.ovpn` that would start programs,
  load plugins, write files or change privileges is refused. Pushed routes are
  ignored, pushed DNS servers are used for that route only.
- **Multi-hop** (`via = "laptop"`): a tunnel's encrypted packets go through another
  tunnel – WireGuard in WireGuard, OpenVPN in WireGuard or the other way round. First
  hop down → second hop blocked, nothing goes direct. Inner MTU set automatically.
- **Network profiles** (`[[network]]`): default route per Wi-Fi name + router MAC,
  e.g. at home direct, everywhere else through the tunnel ("Add the current network").
- **Hotel/train Wi-Fi login**: `shunt captive` / tray item opens a throwaway browser
  that goes direct.
- **Installer**: OpenVPN support, optional privacy on foreign networks (own MAC per
  Wi-Fi, no host name in DHCP, IPv6 privacy addresses).
- **Update check** every 3 hours (can be switched off): notification, tray item and a
  banner with the update command and a copy button.
- **Restart buttons**: tray "Restart service" / "Restart service and app", UI button,
  `shunt restart`.
- `shunt which NAME`: which route each running process takes. The UI warns when an app
  you just routed is still running in its old route (browsers keep their route).
- `shunt import FILE` (with sudo for root-only files like `/etc/wireguard/*.conf`).

### Fixed
- Config editor could overwrite changes made meanwhile (file or other window): saves
  on an old version are refused now, the UI reloads.
- Import/delete/PANIC confirmations could silently do nothing in the desktop window
  (browser dialogs) – replaced by an in-page dialog.
- A DNS server not reachable through its tunnel broke name resolution silently: now
  shown in status, overview and tray (yellow) and as a notification; logged once.
- White text on white select fields with dark GTK themes (Pop!_OS).
- Blank white window in VMs (software rendering).
- Installer: hung on the release lookup (timeouts), could install an older release
  than the current code.
- Orphaned tunnel files no longer block a re-import; clearer permission errors.

### Install / update
```sh
curl -fsSLo install.sh https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/HEAD/install.sh && sudo bash install.sh
```
Afterwards: tray → "Restart service and app".
