# Security

The Shunt decides which traffic leaves through which tunnel. A bug can leak
traffic, so security reports are welcome and taken seriously.

## Reporting

Please use GitHub's **private vulnerability reporting** (Security → Report a
vulnerability) instead of a public issue. Include what you did, what leaked
or broke, and the output of `shunt status --json` and `journalctl -u shuntd`
(remove anything private).

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
- **App rules are best effort**: a program is moved into its route right
  after it starts; a connection opened in the first milliseconds keeps the
  old route. Menu entries made with `shunt desktop` and `shunt run` have no
  such window.
- **Domain rules trust DNS.** Whatever the route's resolver answers is
  routed. On foreign networks use an encrypted `dns.direct` (tls/https).
- **Apps with their own encrypted DNS** bypass domain rules (app, IP and
  port rules still apply).
- **root on the machine** can do anything, including turning Shunt off.

## Verifying downloads

Release tarballs come with `SHA256SUMS` (checked by the installer) and a
build provenance attestation (sigstore). With the GitHub CLI:

    gh attestation verify shunt_linux_amd64.tar.gz --repo Bob-Nixkoenner/The_Shunt

This proves the file was built by this repository's release workflow.
