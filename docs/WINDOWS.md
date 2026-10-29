# The Shunt for Windows

Status 15.10.2026: service, window, installer and kill switch work (tested in a
Windows 11 VM; not yet on a real laptop with Wi-Fi). Branch `windows-service`.

## How it works

The Linux way (cgroups, nftables marks, kernel WireGuard) does not exist on Windows. The
Windows build uses the same userspace core as Android (`internal/splitstack`):

```
Apps ─► wintun adapter "Shunt" (routes 0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1)
          └─► gVisor stack (splitstack)
                ├─ program of the connection = exe path (GetExtendedTcpTable/UdpTable → PID → path)
                ├─ tunnel:<name> → WireGuard (wireguard-go, own netstack per tunnel)
                ├─ direct        → socket pinned to the real interface (IP_UNICAST_IF)
                └─ block         → reset
```

- `shuntd-win.exe` (`cmd/shuntd-win`): Windows service. Config `C:\ProgramData\Shunt\shunt.toml`
  – the same file format as Linux (`internal/winsvc.Translate` turns it into the core's JSON
  and reports what Windows cannot do yet). API: the `/v1` API of shuntd over a Unix socket
  (`C:\ProgramData\Shunt\shuntd.sock`, Windows 10+), served by `internal/winsvc`.
- `shunt-desktop.exe` (`cmd/shunt-desktop`): tray icon, toast notifications, autostart
  (Run key), single instance, window = Microsoft Edge in app mode showing the web UI
  (`internal/ui`, unchanged apart from a `platform` flag that hides Linux-only parts).
  The "Programs" list (`internal/winapps`) shows running programs and their rules.
- Programs are matched by file name (`app = ["firefox"]` → `firefox.exe` anywhere) or by path
  (`exe:C:\Tools\x.exe`). Rules by address, port and domain work as on Linux.
- `link:wifi|ethernet|mobile` routes: direct while the machine is on that kind of network, blocked otherwise
  (flows are cut when the kind changes).
- Network changes (Wi-Fi ↔ cable, new Wi-Fi) are followed every 3 s; the Wi-Fi name picks the
  `[[network]]` profile.
- Start in a route (launchers, "Start an app"): `shunt-desktop.exe run --via ROUTE -- PROGRAM`
  starts the program suspended; the service (`POST /v1/run`) puts it into a named job object
  of that route, then it is resumed. Children inherit the job, so the whole browser stays in
  the route (the Linux cgroup). The owner lookup checks the job (`IsProcessInJob`) and hands the
  engine a pinned app ID (`splitstack.Pinned`). Job names are kept in `state\jobs.json` for a
  service restart. Not in the job: the browser's updater service, a browser started by a link
  from another program (Explorer starts it), Edge preloaded by "Startup boost".
- Launchers (`internal/winapps/launchers.go`): Start menu shortcuts in the user's folder
  "The Shunt Launchers" to `shunt-desktop.exe run …`, described in `%APPDATA%\Shunt\launchers.json`.
  Chromium-family launchers get a new data folder `%USERPROFILE%\ShuntProfiles\<name>`. Existing
  Chromium profiles are not linked as on Linux: on Windows the browser binds cookies and saved
  passwords to its user data directory (App-Bound Encryption), a second directory cannot read them
  and deletes them from the shared profile (tested with Brave, same `Local State` keys).
- DNS guard (always on): Windows Firewall blocks port 53 for the DNS client service (Dnscache)
  except towards the adapter's DNS address. Without it, "smart multi-homed name resolution"
  asked the router's DNS (on-link, past the routes) in parallel to The Shunt. With the kill
  switch it stays while the service is stopped; without it a stop lifts it. Also lifted by
  `shuntd-win killswitch-off` and uninstall. It also blocks LLMNR/mDNS of the DNS
  client and NetBIOS name queries of the kernel (UDP 5355/5353/137), which broadcast names to the
  local network. The direct route uses the network's
  DHCP DNS server unless `dns.direct` is set.
- Kill switch (`[daemon] kill_switch`, **on by default** since 0.7.1; `false` turns it off):
  Windows Firewall blocks all outgoing traffic except the service, the adapter's address
  (= apps whose packets entered the split), the local network (without its DNS, ports 53/853)
  and DHCP. It stays while the service is stopped, after a crash and across a reboot, so nothing
  leaks before the service runs; only `kill_switch = false` (Configure), uninstalling or
  `shuntd-win killswitch-off` as Administrator (emergency) lift it.

## Install

**Setup.exe** (from the releases, built with Inno Setup from `packaging/windows/the-shunt.iss`): double-click, accept the administrator prompt, click through; restart Windows once if the tunnels stay down. Update: run the newer one over it; uninstall via *Settings → Apps*. Tunnel files: WireGuard `.conf` or Tailscale/Headscale `.ts` (Configure → Tunnels).

`packaging/windows/build.sh` builds `dist/the-shunt-windows-amd64.zip` (wintun.dll pinned by
checksum); `install.ps1` / `uninstall.ps1` inside. Details in `packaging/windows/README.txt`.

## Tor and SOCKS

`driver = "tor"` (Configure: Add a tunnel, Tor) runs `tor\tor.exe` from the install folder as a child of the service; bridges `snowflake`, `obfs4`, `meek` use `tor\pt\lyrebird.exe`. tor.exe and the transports always go out direct (the service adds those app rules) and the kill switch lets them send. Apps on the Tor route: TCP only, names through Tor, `.onion` works, an own circuit per app (`isolate`). `socks = "127.0.0.1:1080"` on any tunnel opens a SOCKS5 proxy whose connections leave through that tunnel (TCP; no UDP ASSOCIATE yet).

## Not yet

OpenVPN (the Android trick needs fd passing; Windows needs another way), groups, DNS filter levels per rule/tunnel/network (the default level works, lists are downloaded straight over the real network), app firewall, restricting
the API to certain users (today every local user may use it; config files stay admin-only),
code signing (SmartScreen warns), WireGuard `allow_lan`, `via` hops are untested on Windows.

## Testing

- Unit tests run on Linux (`go test ./internal/...`).
- VM: VirtualBox, Windows 11 (Home is enough), NAT with `--nat-localhostreachable1 on` so the
  guest reaches the host's loopback as 10.0.2.2. Test tunnels: `go run ./test/android/wgserver
  -listen 127.0.0.1 -host 10.0.2.2 -out DIR` (then import `DIR/home.conf`, `work.conf`).
- An interactive window cannot be started from SSH; use `schtasks /create … /ru USER /it` + `/run`.
