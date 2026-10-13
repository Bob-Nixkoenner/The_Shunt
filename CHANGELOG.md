# Changelog

## Unreleased

**Wi-Fi vs. cable, and security fixes from a code review.**

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
- **Fix: UDP inherited the route of an earlier flow with the same ports.** A program
  sending from a source port another program's UDP flow just used (same destination)
  took that flow's route – seen as a sporadic "LEAK" of the block route in the leak
  test, and usable to leave a tunnel or block. Only TCP keeps its connection's route
  now; UDP is classified by its program on every packet.
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
