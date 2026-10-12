# The Shunt

**Per-app and per-destination split tunneling for WireGuard on Linux.**
Decide which traffic takes which tunnel – by application, IP range or port – with a
kill switch that holds even when the daemon crashes. Open source (Apache-2.0),
no telemetry, no accounts, bring your own WireGuard servers.

> 🇩🇪 *Split-Tunneling pro App, IP und Port für WireGuard unter Linux – fail-closed,
> ohne Telemetrie. Design-Dokument (deutsch): [docs/DESIGN.md](docs/DESIGN.md)*

> ⚠️ **Status: proof of concept (phase 1).** It works and is tested end-to-end, but:
> **DNS is not routed yet** – a tunnelled app's DNS queries still go out via the
> system resolver (phase 2). Don't rely on it for anything serious yet.

```console
$ shunt run --via tunnel:vps -- firefox      # Firefox through the VPS, rest direct
$ shunt run --via direct -- steam            # escape a tunnel default route
$ shunt run --group torrent -- qbittorrent   # use rules from the config
$ shunt status
$ shunt panic on                             # drop everything, now
```

## What works (phase 1)

- Several WireGuard tunnels at once, each in its own routing table
- Rules by **process group**, **CIDR** and **port**, first match wins
- `shunt run` starts a program inside a route; children inherit it
- **Kill switch built into the routing table**: tunnel down, interface deleted or
  daemon stopped → tunnelled traffic gets *unreachable*, never the physical NIC
- **IPv6 strict**: tunnels without IPv6 block IPv6 instead of leaking it
- Panic mode, optional boot lockdown, DDNS endpoint re-resolution
- Kernel WireGuard, with in-process wireguard-go as fallback
- wg-quick files are imported; `PostUp` & co. are **ignored** (no root shell
  hooks from config files you got from somewhere)
- Unprivileged CLI talking JSON over a Unix socket; GUIs can plug in the same way

## How it works

```
shunt run ──► shuntd moves the process into a cgroup (apps/via/tunnel-vps)
                         │
nftables (route hook):  socket cgroupv2 … → meta mark 0x530002  → kernel re-routes
                         │
ip rule fwmark 0x530002 → table 5302:  default dev sh-vps
                                       unreachable default metric 4096  ← kill switch
```

Details, threat model and roadmap: [docs/DESIGN.md](docs/DESIGN.md).

## Build & install (Pop!_OS / Ubuntu)

```sh
sudo apt install nftables wireguard-tools   # wireguard-tools only for `wg genkey`
go build -o bin/ ./cmd/shuntd ./cmd/shunt   # Go toolchain is fetched automatically

sudo install -m755 bin/shuntd bin/shunt /usr/bin/
sudo install -d -m700 /etc/shunt/tunnels
sudo install -m600 my-vps.conf /etc/shunt/tunnels/vps.conf
sudo install -m644 packaging/shunt.toml.example /etc/shunt/shunt.toml
sudo groupadd --system shunt && sudo usermod -aG shunt "$USER"   # re-login afterwards

sudo shuntd -c /etc/shunt/shunt.toml check  # dry run: validates and prints the nft ruleset

sudo install -m644 packaging/systemd/shuntd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shuntd
```

Uninstall / emergency exit: `sudo systemctl disable --now shuntd && sudo shuntd cleanup`
(stopping the daemon alone keeps the kill switch active – on purpose).

## Testing

```sh
go test ./...                               # unit tests, golden nft ruleset
sudo ./test/integration/run.sh              # end-to-end in network namespaces
sudo SHUNT_DRIVER=userspace ./test/integration/run.sh
```

The integration test builds a small internet in two network namespaces (WireGuard
server + "whoami" HTTP server) and checks every route, the kill switch, panic mode
and fail-closed behaviour after the daemon stops.

## License

Apache-2.0
