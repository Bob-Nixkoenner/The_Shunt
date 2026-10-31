# Changelog

## Unreleased

- Lab tests (Linux), Tor: new H04–H09, H11 (tor hangs/dies, isolation per rule, obfs4 bridges, Tor over WireGuard, .onion names, system services and reboot under tor-all); the gateway judges only the tor-all part (LABMARK), tor's old sockets get their process name, VM reboots keep DHCP working.
- Lab tests (Linux): P01 reads the clock warning in any language; A06–A08 allow the distro's own direct background traffic (NTP, connectivity check, Arch updates) with default route direct; a system tor.service in the client is switched off before a test; G01/G02 scan with `[inbound]` on.
- Leak test (Android, Windows): a working Tor tunnel no longer shows "blocked". The probe went through the tunnel's DNS server, which Tor does not carry; it now hands names to Tor like the apps do and checks check.torproject.org. A blocked Tor row shows the reason.
- Linux: gateway mode (`[gateway]`, `[[gateway.group]]` with `interfaces` and `route`, stage 1, see docs/GATEWAY.md): devices, VMs and containers behind chosen interfaces go through The Shunt with their own route per group. Kill switch for forwarded traffic (no fallback to direct), NAT for direct groups, IPv6 from clients dropped, groups kept apart, clients reach only DHCP/DNS/ICMP of the host, panic and tor-all cut them off. `shunt gateway status`, config check findings, netns integration test. Tor as group route and the Shunt resolver for clients come in stage 2.
- Window (Linux and Windows): three levels instead of Normal/Expert, chosen under View: **Simple** (Overview, VPN, Apps, DNS, Speedtest and View; Tor, ports, Configure, rules, network profiles, incoming protection and the fine-tuning are hidden, existing Tor tunnels stay as a plain card, the emergency switch stays visible while it is on, "Everything else goes" moves to the VPN tab, only really bad check findings show), **Pro** (everything) and **Opsec** (everything, violet accent and an "OPSEC" band in the header; status colours stay green/red and always come with a word). Fresh installs start in Simple; Normal becomes Simple and Expert becomes Pro (also in the ui-state file). Hidden settings keep working, and a banner lists the ones in use.
- One table (`levels.js`) says which tab, card and field shows in which level, instead of checks spread over the page.
- Incoming protection (`[inbound]`: the switch, allowed ports, per tunnel, per network profile, notes on the Ports tab, the question on a new network) shows in Pro and Opsec only. On Windows the switch, the allowed ports and the per-network setting are now in the window too (the service supported them already); per-tunnel inbound stays Linux only.
- Opsec assistant: switching to Opsec lists what it sets, one switch each (on by default), and changes nothing before you confirm: kill switch (Windows), network blocked at boot (Linux), random MAC and no DHCP host name (Linux), no Wi-Fi login check (Linux), incoming connections closed, clock check (Windows), TCP timestamps off (Linux), stricter security check (`daemon.config_check = "strict"`). Settings a system always has, or does not have, show as such: "no ICMP timestamp answers" is always on under Linux and not available on Windows. Statistics and the speed test history are kept: Opsec is about what the network and others see, not what stays on this computer. Switching back offers to undo each change. The help says honestly that Opsec is no guarantee.
- Security check: new `daemon.config_check` (`normal` | `strict`, default normal). Strict raises every finding one level (info → warning → bad); an OpenVPN file without tls-crypt/tls-auth, allowed DoH/DoT and `default_route = "direct"` become bad (`shunt check` exits 1), and every rule with `route = "direct"` becomes a warning of its own (`rule.direct`). Findings raised this way carry `strict: true`; the window shows them as banners.
- German: the levels are Einfach / Profi / Opsec everywhere, the Android mode too (Simple / Pro in English, was Normal / Pro).
- Android: the same three levels (View tab → "Settings shown"), replacing Normal / Pro: old Normal becomes Simple, Pro stays Pro, a fresh install starts in Simple (the old `pro` field is still written, for going back to an older version). One table (`Levels.kt`) says what shows where. Simple hides adding Tor, bridges, New identity, the built-in Tor / Orbot switch, the emergency switch (visible while on), tunnels through other tunnels, routes per network and the DNS server list (each visible while set); existing Tor tunnels stay as a plain card.
- Android Opsec: violet accent (same colours as the window; status green/red unchanged), a slim OPSEC band in the header, the emergency switch on the Status tab (red frame). The assistant lists what Opsec means on Android: the stricter check (a switch of the app, on by default, offered back when leaving Opsec), Android's own kill switch and Private DNS (shown with their state and a button to the system settings: only the user can change them), DoH blocking (always on), random MAC (set by Android), and honestly as "not available on Android": Wi-Fi login check, incoming connections, clock check, TCP/ICMP timestamps. Statistics and history stay.
- Android layout: tidier text at every font size: tunnel card headers keep the name and move Rename/Delete below when space is short, button groups wrap, checkboxes and link buttons line up with their text, key/value rows stay aligned, long names end in "…"; paddings and gaps come from one place (`Gap`).
- Android strict check: with Opsec's "Stricter security check" the Status tab shows banners: all other apps going direct (also per Wi-Fi/mobile profile) and OpenVPN files without tls-crypt/tls-auth as bad, apps going direct as warnings (Pro and Opsec only). The core's `CheckOpenVPN` summary has a new field `tls_wrap`.
- Fix: the "Port rules" list on the Ports tab stayed empty (a function of the open-ports table had the same name); the open-ports table no longer fails when nothing listens.
- Linux: replies to connections forwarded for containers and VMs behind this machine now come back through a tunnel that is the default route. The leak guard dropped them (they carried the tunnel's mark); packets that arrive from the tunnel are exempt now.

## v0.7.1-rc20

- Android Tor: the leak test no longer calls a Tor that is still starting "BLOCKED". It waits (up to 90 s) until the built-in Tor is through the network, probes with a longer limit (30 s per request, the first circuits are slow) and otherwise says "Tor is still starting (n %) - run the test again in a moment" (verdict `starting`) or "Tor does not start" with the reason (verdict `error`, new `progress` and `detail` fields). The notes are translated on Android and in the window (German included).
- Android Tor card: shows why Tor does not start (exit code or signal, last log line, exec error) instead of a bare "starting"; a Tor that is up shows "up" (was "waiting" with "handshake never"); while it boots the pill says "starting". Pro mode: button "Start now" ends the wait before the next start. Tor tunnels never sleep with "keep only used tunnels connected" (Tor starts with the app; test added).
- UI: more cards fold (DNS filter, Rules, Never block, DNS settings and servers, Port rules, Speedtest, Routing, Service, Privacy and protection, App firewall, Traffic and blocks, Settings shown, Look); the state is remembered like for the other cards.
- UI: links (Wi-Fi, cable, mobile) that are not connected are left out of the lists: Apps tab (route choice; a saved route stays), "DNS per route", "In effect now" in the DNS tab.
- Overview: tunnel cards show their type (WireGuard, OpenVPN, Tailscale, Tor, plus SOCKS when the tunnel has a SOCKS5 exit); the "names blocked" counter follows the range switch (1 h, 24 h, 7 d, 30 d) instead of "today".
- Security check: "What does this mean?" in plain words for the OpenVPN findings (no tls-crypt/tls-auth, CBC, compression, remote-cert-tls).
- Tor tunnel cards show the current exit (country, relay name, address; local display only) and the number of hops of the circuit new connections use (a bridge counts as first hop), read from tor's control port; new status field `circuit` on Tor tunnels; refreshed after "New identity". Android: planned (docs only).
- Leak test on a Tor tunnel is no longer a WARN: Tor's DNS port cannot answer the TXT query that shows the resolver ("server misbehaving"), so for Tor routes the probe asks check.torproject.org (IsTor) instead and the tile says "inside Tor". New probe fields `tor`, `is_tor`, `tor_error`.
- Config check: findings can carry a plain-words `help` text; the missing tls-crypt/tls-auth note now explains what it is and what to do (window and `shunt check`, German included).

## v0.7.1-rc19

- Lab tests only: nmcheck DNS counts as info, N01 measures how fast the rules come back, the lab client reconnects without a link.
- Tor bridges explained in plain words (Android card with an info button, window: "What is a bridge?" under the Tor form and in the tunnel list, `shunt tor help`): what a bridge is, when you need one, snowflake / obfs4 / meek / webtunnel / own lines, recommendation. "New identity" and the emergency switch "Everything through Tor" got short explanations. German included.
- Android: Normal / Pro mode (new Settings tab, default Normal, saved). Adding Tor, bridge choice, "New identity" and the emergency switch show in Pro only; a Tor tunnel that exists stays on its card, and the emergency switch stays visible while it is on.
- Speedtest history: the last 3 finished tests (date, network profile, median ping/download/upload per route) are kept in `speedtest-history.json` in the user config folder (mode 0600, no addresses or network names); list "Recent measurements" in the tab and `shunt speedtest --history`.
- Link routes (Wi-Fi, cable, mobile) are only offered while that connection is really up: speedtest tab and `shunt speedtest` (also its data estimate), the run, launcher and firewall-prompt route lists and the per-app route list. A saved rule on a link that is down stays visible and editable. New status field `routes_down`.
- `tor-all` is now a strict emergency mode (Linux): besides sending every app through Tor, a second nftables table (`shunt_emerg`) drops everything that leaves the machine except the tor process talking to its bridges (or, without bridges, to the relays of its cached consensus, refreshed every 20 minutes), DHCP and IPv6 neighbour discovery. No fall back to direct when tor dies, on panic off, on a network change or while shuntd is stopped (the table stays). Snowflake/meek/webtunnel bridges hide their destination: then the tor process may connect anywhere, nothing else. Switching on is refused without a relay list or bridges, and for a Tor tunnel with `via`.

## v0.7.1-rc18

- Speedtest tab (Linux): measures every route one after the other (Cloudflare by default, M-Lab NDT7 as an option with an info button – M-Lab publishes the measurement with the IP, not offered over Tor), random order of routes and measurements, median over 1–5 rounds, also `shunt speedtest`.
- Config check: `shunt check` and a folded list in the window point out risky or redundant settings (DNS, kill switch, boot lockdown, network profiles, OpenVPN files); daemon warnings are translatable.
- German command line (`shunt --help`, status, tor, ports, speedtest, leaktest …) and a German `install.sh`/.deb; `--json` and table headers stay English.
- Fixes: the header and the save bar are opaque again (WebKit let the content shine through); the Tor "no connection" notice waits 30 s so it does not pop up while Tor is starting; `install.sh` builds lyrebird in `/var/tmp` (a small `/tmp` made the build fail silently).
- SOCKS5 exit per tunnel (Linux): `socks = "127.0.0.1:1080"` under `[tunnel.X]` opens a local SOCKS5 proxy (CONNECT and UDP ASSOCIATE, names resolved inside the tunnel) whose connections leave through that tunnel; `shunt socks` lists them, the form has a field under "Advanced".
- Tor tunnels (Linux): `driver = "tor"` runs the system `tor` as a child of shuntd and offers it as a route (`tunnel:tor`) with a transparent TCP proxy, DNS over Tor's DNSPort, `.onion` names only through Tor, own circuits per rule, UDP and ICMP rejected. Bridges (obfs4, snowflake, meek, webtunnel, or your own lines) come with lyrebird, shipped in the release archive, the .deb (`Depends: tor`) and the installer. Tor can run through another tunnel or link (`via`).
- Android: a Tor tunnel type for the split stack and the app ("Add Tor"), tested in the emulator with Orbot (Power User Mode on, so it runs without its own VPN): TCP through Orbot's SOCKS port, names resolved through the same port (Orbot's DNSPort is random), `.onion` names work, no UDP; the tunnel card says "down" and apps on it are blocked while Orbot is not running.
- Android: Tor is built in (libtor.so from tor-android, lyrebird for snowflake/obfs4/meek bridges): own circuits per app, bootstrap bar, "New identity", bridge choice, and an emergency switch "Everything through Tor"; Orbot still works as the alternative. "Get Orbot" opens F-Droid's page when F-Droid is installed. A weekly workflow (`tor-watch`) opens an issue when Tor, tor-android or lyrebird has a new release.
- `shunt tor status|newnym` and `shunt tor-all on|off|status` (emergency switch: everything through Tor, survives restarts); the window gets a Tor form, an overview card with the bootstrap state, a "New identity" button and an "All via Tor" button. German texts included.
- Windows: `driver = "tor"` tunnels (the setup brings `tor.exe` and `lyrebird.exe` from the Tor Expert Bundle, pinned by checksum, into `tor\`): the service starts tor as its child (ends with it), apps on the Tor route go through tor's SOCKS port with their own circuits, names are resolved through Tor, no UDP. The kill switch lets tor and its transports send like the service itself. `socks = "127.0.0.1:1080"` under `[tunnel.X]` also works on Windows (TCP, names resolved in the tunnel).
- Windows: inbound protection with `[inbound] enabled = true` and `inbound = "closed"|"lan"|"open"` per network profile, as on Linux. Windows Filtering Platform filters (own sublayer above Windows Firewall) block new inbound connections; `lan` opens the listed ports for private addresses only; the tunnel adapter is never opened; DHCP, router discovery and loopback keep working. Off unless enabled.
- Windows: optional clock check (`[daemon] clock_check = true`, off by default; switch under Configure): every 10 minutes The Shunt asks a few web servers for the time through the default route and warns in the status when the clock is more than 90 seconds off.
- Tor Windows bundle: the weekly Tor watch checks the pinned Expert Bundle (checksum, GPG signature of the Tor Browser Developers key, newest version) and the lyrebird pin.
- Linux: shuntd checks every second that its firewall rules are still loaded and puts them back (with a warning in the log) when something else removed them – another VPN, a firewall tool, `nft flush ruleset`. Before, traffic left directly until the next reload (lab N01).
- Linux: a tunnel's own address is no longer reachable from other interfaces. Neighbours on the local network could ask "who has 10.66.0.12?" (ARP) and learn that this machine uses a VPN and which address, or send packets to it (CVE-2019-14899). New chain `tunnel_addr_guard` and arp table `shunt_arp`; found by the test lab (M01, M02).
- Linux: forwarded traffic (containers, VMs and devices behind this machine) now follows the default route. It used to take the main table, past the tunnel and its kill switch, also with the tunnel up (lab M06, M09).
- App firewall (`ask`/`block`): programs that start at once are held too – shuntd rescans when exec events are lost and every 250 ms while the firewall is on.
- Panic mode: one renderer for the panic, boot lockdown and the coming emergency tables (output byte-identical, golden tests). `panic_kill = true` also ends every program in a tunnel group when panic goes on (default off; via `cgroup.kill`, no extra capability).
- shuntd compares the system clock with the time web servers report through the tunnel (every 20 minutes, default route a tunnel) and warns in `shunt status` when it is more than 90 seconds off. It sets nothing, and nothing is asked in the clear.
- Linux: `daemon.tcp_timestamps = "off"` switches TCP timestamps off while shuntd runs (default keeps the system setting): direct connections no longer show a neighbour the uptime.
- Linux: ICMP timestamp, address-mask and info requests are not answered (no clock/uptime fingerprint for neighbours).

## v0.7.1-rc17

- Languages: the window, the tray menu and the notifications speak the language of the system – German now, English otherwise – and a language picked under View → Language applies to all three (the tray follows within seconds). A language is one file (`internal/i18n/lang/<code>.json`: the English text is the key, a missing translation shows the English text), so more can follow. `SHUNT_LANG=en` overrides both for a single run. Android speaks the language Android gives the app (system language, or the per-app language on Android 13+) from the same catalog, packed into the app. The Windows setup follows the language of Windows (German or English). The command line and `install.sh` are still English; so are logs, JSON output and config keys. A check in the tests lists texts that have no translation yet.
- Configure tab tidied up: "General" is split into Routing and a new "Privacy and protection" card (host name, MAC, incoming connections, network at boot in two columns, shorter explanations); a network profile is one compact card with its settings in a grid, and what the profile sets itself is marked with a coloured bar, so the few overrides stand out from "as under General". Same settings, same keys.

## v0.7.1-rc16

- Installer and .deb: when the privacy option switches the MAC on, networks you trust already (a profile with `inbound = "lan"`/`"open"` or `dhcp_hostname = "send"`, e.g. home) get `mac = "permanent"` and keep the real MAC, so router reservations at home keep working; the installer names them. Profiles that set a MAC themselves are left alone.

## v0.7.1-rc15

- Installer and .deb: the privacy option now covers the cable and the device IDs too. Saying yes (the .deb on its first install) also puts `dhcp_hostname = "none"` and `mac = "stable"` under `[daemon]` in `shunt.toml` (only keys that are not set yet), so the cable MAC, the DHCPv6 DUID and the client ID differ per network and a network's first connection is covered. An install from before is asked once, only in a terminal: an update from the app or a .deb update never changes the MAC at home unasked. At home: network profile → MAC "the real one".
- Installer: questions count as asked only with a real terminal (`/dev/tty` exists without one too, e.g. ssh without `-t`); without one the defaults apply, as before.

## v0.7.1-rc14

- Desktop window / web UI: tabs like the Android app – Overview, VPN, Apps, DNS, Ports, Configure, View. A Normal/Expert switch under View hides rules, ports, own DNS servers, multi-hop, launchers and firewall details in Normal (they keep working; a banner lists the ones in use). Narrow windows: tabs wrap, tables stack.
- Dependencies: `cilium/ebpf` v0.22.0 (GO-2026-6238, reachable through the start protection).
- Open ports and DNS blocks per app (Linux): shuntd lists the listening sockets and names their program by its cgroup (`shunt ports`, Ports tab), with where each can be reached from (this machine, the network, a tunnel). The DNS filter names the program behind each blocked query (`shunt blocks`, Apps → "Who asks for blocked names").
- Inbound protection (Linux): `[inbound] enabled = true` closes incoming connections on networks you have not trusted (answers, DHCP, neighbour discovery and ICMP errors still pass). A `[[network]]` profile can say `inbound = "lan"` (the ports in `inbound_allow` / `inbound.allow` from private addresses) or `"open"`; each tunnel too (closed unless it says otherwise). On an unknown network the status asks whether to trust it. `shunt inbound`, settings under Configure → General, per network and per tunnel. Off by default (on a server it would close SSH).
- MAC address per network (Linux, NetworkManager): `mac = "random" | "stable" | "permanent"` under `[daemon]`, per network profile as well (e.g. the real one at home); also in Configure → General and per profile. Wi-Fi and cable. With random or stable the device's own IDs leave DHCP and IPv6 too: the DHCPv6 DUID was the same on every network (derived from the machine ID), now it follows the MAC (random) or the profile (stable); the DHCPv4 client ID follows the MAC; IPv6 addresses use stable-privacy instead of EUI-64 (MAC inside). A new MAC applies from the next connection, a connection in use is not cut. Off unless set.
- No host name in DHCP now covers a network's first connection on NetworkManager 1.52+: the defaults said `false`, which these versions ignore (they read a number), so a newly joined network still got the host name until The Shunt had set the profile. Now `0`; `install.sh` and the .deb fix the file they wrote earlier (`90-shunt-privacy.conf`).
- The network privacy settings never change a profile while it connects (NetworkManager 1.54 then never finishes DHCP), and reach NetworkManager at boot too (it may not answer yet when shuntd starts). A connection that already runs with the defaults is not reapplied (that restarted DHCP for nothing).
- Linux: with a tunnel as default route, IPv6 neighbour discovery (router and neighbour solicitations, neighbour advertisements) got the tunnel mark and was dropped, so the local network gave no IPv6 to apps that go direct. It now takes the main table, as DHCP does (and as the boot lockdown already allowed).

## v0.7.1-rc13

- Windows: the kill switch moved from Windows Firewall rules to the Windows Filtering Platform (new package `internal/winsplit/wfp`, derived from wireguard-windows, MIT). Windows' own allow rules (core networking DNS, push notifications, store apps; 124 on a fresh Windows 11) punched through the old "block outbound" policy, so DNS, push and telemetry left the network while the service was stopped, after a crash and at boot. The new filters sit in a sublayer above the firewall and permit only the service, the Shunt adapter, loopback, DHCP/NDP and private local networks (not their DNS); DNS goes only to The Shunt. They are persistent: they stay while the service is stopped, after a crash and across reboots. Measured in the test lab: 24 of 27 Windows tests pass (7 before); stop, crash, reboot, IPv6, TunnelCrack LocalNet and push connections no longer leak.
- Windows: the kill switch is **on by default** (`[daemon] kill_switch = false` turns it off). Only turning it off, uninstalling or `shuntd-win killswitch-off` (emergency, as Administrator) lift it; stopping the service or shutting Windows down no longer does. The firewall rules of the old kill switch are removed at the next start.
- Linux: answers to connections that came in through a tunnel (SYN-ACK, RST, ICMP, UDP replies) leave through that tunnel. They took the main routing table and showed the tunnel address on the local network.
- DNS filter lists are downloaded the way apps without a rule go, DNS included. Linux asked the name on the local network (the lookup had no route mark); Windows downloaded them straight over the physical network.
- No host name in DHCP (Linux, NetworkManager): `dhcp_hostname = "none"` under `[daemon]`, per network profile `"send"` (e.g. at home); also in Configure → General and per profile. The Shunt sets NetworkManager's profiles itself, because NetworkManager has no working global switch for it (1.46 none, 1.54 ignores the default for unset profiles). Off unless set.
- Captive portal check: the same request as NetworkManager's own check (no Go User-Agent, no gzip), so a network cannot tell The Shunt apart.
- .deb: writes the network privacy settings `install.sh` offers (own MAC per Wi-Fi, IPv6 privacy addresses), once; removing the package removes them.
- App rules list the menu entries that start one of their apps outside the rule's route ("start in the route from the menu"): an app rule catches a program only after it started, so its first connection could go the old way.
- Android docs: without "Block connections without VPN" Android itself lets a little past the VPN (DNS while it starts, sockets opened before it); with always-on and the block nothing of an app got past in the lab.

## v0.7.1-rc12

- Update button for source builds: a build made from source (`src-<sha>`) compares commits, so the app never offered to install the newest release itself and only showed the copy-command fallback. The update info now carries the release tag that "Update" installs (`internal/update`).
- Android: first start shows what the VPN service can see (installed apps, destinations and DNS names of the routed apps, keys) and what happens with it (nothing leaves the phone; GitHub for filter lists and api.ipify.org for the leak test, only when used), with Accept and Decline. Nothing runs before Accept. A "Privacy" section on the Status tab links to the policy.
- Website and privacy policy (English and German) and a legal notice on GitHub Pages: https://bob-nixkoenner.github.io/The_Shunt/

## v0.7.1-rc11

- Windows: launchers and "Start an app", as on Linux. A launcher is a Start menu entry (folder "The Shunt Launchers") that starts a program with extra arguments in a route; existing Firefox profiles get a launcher each. Chrome, Brave, Edge, Vivaldi and Opera launchers get a new profile folder of their own in `%USERPROFILE%\ShuntProfiles`; existing profiles of these browsers cannot be shared with a launcher on Windows (the browser binds cookies and saved passwords to its data folder: a second folder cannot read them and the browser deletes them from the profile, tested with Brave).
- Windows: `shunt-desktop.exe run --via ROUTE -- PROGRAM ARGS` starts the program suspended, the service puts it into a job object of the route and only then lets it run; its children inherit the job, like a cgroup on Linux. The route wins over program rules (destination rules still come first), a route that does not exist blocks. Jobs survive a service restart (`state\jobs.json`). New service endpoint `POST /v1/run` (`pid`, `route`), `GET /v1/procs` lists processes and their route (launchers show "running via ...").
- Uninstall removes the user's launcher shortcuts, never `ShuntProfiles`.
- WireGuard through WireGuard (multi-hop, `via` on a WireGuard tunnel) in the userspace core: Android ("through" on the tunnel card, now for WireGuard too) and Windows. The inner tunnel's socket lives in the carrier's netstack. Tested with a server reachable only inside the carrier (Go test and emulator).
- Android: network profiles: apps without a rule can take another route on Wi-Fi or on mobile data ("Where traffic goes"). By network name (SSID) is not in yet.
- Android: fixed: the app never noticed a change between Wi-Fi and mobile data. It watched its own default network, which is the VPN itself, so tunnels were not re-opened on the new network and Android was not told the new underlying network. It now watches the real networks. Emulator test extended (DoH, `link:` routes over Wi-Fi and mobile data); 24 of 24 checks pass.
- Android: routes `link:wifi` and `link:mobile` (direct, but only over that kind of network; blocked on the other) in the route pickers; the app tells the core which kind of network it is on (also the base for network profiles). Public DoH endpoints and Firefox's canary domain get NXDOMAIN, as on the desktop.
- Windows: fixed a DNS leak. With "smart multi-homed name resolution" Windows sent every query also to the DNS server of the real network (the router, on-link, so past every route), even when the app's traffic went through a tunnel. Windows Firewall now blocks port 53 for the DNS client service except towards The Shunt's adapter ("Shunt DNS" rules, removed when the service is stopped on purpose; after a crash names resolve again once the service is back). Tested in the VM with pktmon: 10 of 10 queries through the tunnel, none to the router (before: every one to both).
- Windows: LLMNR, mDNS (DNS client) and NetBIOS name queries (UDP 5355/5353/137) are blocked by the same guard: Windows broadcast names it could not resolve (typos, bare host names, WPAD) to the whole local network. Measured in the VM: 72/189/108 packets without the rules, 0 with them.
- Windows and Android: Firefox's canary domain `use-application-dns.net` gets NXDOMAIN (Firefox then keeps its DoH off), and on Windows the well-known public DoH endpoints too unless `dns.allow_doh` is set, as on Linux. The list moved to `internal/doh`, shared with the Linux DNS proxy.
- Windows: after sleep or hibernation the tunnels start new sessions at once (power event of the service). Go's clock on Windows does not count the sleep, so WireGuard took its keys for fresh while the server had dropped them, and traffic stalled for 15-30 s (reproduced by freezing the VM for 4 minutes; the VM itself cannot sleep, so the power event is untested there).
- Windows setup: starts the tray as the user, never elevated (the "Start The Shunt" checkbox ran it as administrator before, and with it every app it started), and also after a silent install or update (hidden in the tray).
- Windows: the direct route asks the DNS server the network hands out (DHCP), as on Linux, when `dns.direct` is not set (was 1.1.1.1): names only the router knows (fritz.box, the NAS) keep working. Followed on every network change.

## v0.7.1-rc10

- DNS filter: HaGeZi's DNS blocklists (https://github.com/hagezi/dns-blocklists, GPL-3.0, thank you) join RPiList as a source. A list is written `hagezi:<file>` (`hagezi:pro` is `adblock/pro.txt` there; the adblock format also blocks subdomains). New defaults (in `dnslists/defaults.toml`, page `docs/DNS-LISTS.md`): `low` = Multi LIGHT + Threat Intelligence mini (instead of easylist) and the RPiList phishing/malware lists, `normal` adds Multi PRO, `paranoid` adds Multi PRO++. Only configs without a `[dns_filter]` section get the new defaults; an existing section is left as it is. The DNS filter tab lists the HaGeZi lists (all-round, threats/scams/pop-ups, Windows) with their sizes.
- Android: the filter tab offers the HaGeZi lists (all-round with the mobile-sized "pro mini", threats and scams, trackers built into Samsung, Xiaomi, Huawei, OPPO/Realme, Vivo, Amazon and TikTok). New installs start with Multi PRO mini and the RPiList phishing list; settings of existing installs keep their lists.
- New screenshots in the README, `test/mockd` (fake daemon with invented data to take them).

## v0.7.1-rc9

- Linux: "Install update" shows how far the installer got (step n/7 and what runs now), says when it is done, and shows the reason and the log path when it fails. Before it stayed on "Installing..." for 10 minutes whatever happened. The installer prints `SHUNT-RESULT ok|failed` for this (when started with `SHUNT_YES=1`), the app reads `update.log` and checks that the installer still runs. An update running while the window restarts is picked up again.
- Linux: fixed the installer's dry run failing with `unsafe identifier` when the update was started from the autostarted tray app (its cgroup path contains `\x2d`). `shuntd check` now renders for the service's cgroup instead of the caller's.
- Tray (Linux, Windows): the icon shows the number of active tunnels (connected, or idle and connecting on demand) as a badge.
- Android: the status bar icon shows the number of active tunnels; refreshed on every status change and every 10 minutes from the existing watchdog timer.
- Android: the Apps tab keeps the app list and icons for the process (cleared when an app is installed or removed) instead of asking the package manager and redrawing every icon on each visit; the Filter tab counts list sizes only when a file changed and stops polling once all enabled lists are downloaded (it re-read all lists every 5 s before).

## v0.7.1-rc8

- Android: target and compile SDK 36 (Google Play requires it for new apps). Native libraries (Go core, OpenVPN) are built with 16 KB page alignment (Play requirement, also needed on Android 15+ devices with 16 KB pages).
- Android: versionCode now includes the rc number (`(major*10000+minor*100+patch)*100+rc`, 99 without rc), so every upload to Google Play gets a higher code. rc7 and older had 701 for all builds; newer builds are higher and install over them.
- Build: Android Gradle Plugin 8.10.1.

## v0.7.1-rc7

- Android: two flavors. `github` is the APK as before. `play` is for Google Play: no `REQUEST_INSTALL_PACKAGES`, and the update section only tells that a newer version exists and opens the Play page (no download or install). The release now also carries `shunt-<tag>-play.aab` (signed with the release key as upload key; listed in SHA256SUMS). Local debug APK path: `app/build/outputs/apk/github/debug/app-github-debug.apk`.

## v0.7.1-rc6

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
