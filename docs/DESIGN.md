# Design: Shunt – Split-Tunneling & DNS-Router für WireGuard

> **Status:** v0.7 – Phasen 1–3, Sicherheits-Review, OpenVPN, Multi-Hop und Netzwerkprofile umgesetzt (siehe §11–15) · **Lizenz (geplant):** Apache-2.0
> Binaries: `shuntd` (Daemon), `shunt` (CLI). Repo: github.com/Bob-Nixkoenner/the_shunt

---

## 1. Ziel

Ein Open-Source-WireGuard-Client, der entscheidet, **welcher Traffic welchen Weg nimmt** – pro App, IP, Domain, Port oder Dienst – und **welcher DNS-Server für welchen Weg** zuständig ist. Linux (Pop!_OS) zuerst, Architektur von Anfang an portierbar (Android, Windows, macOS).

Kurz: *Rethink DNS für den Desktop, mit Kernel-Speed.*

### Ziele

- Split-Tunneling pro **App**, **CIDR**, **Domain**, **Port/Protokoll**, **ASN-/IP-Liste**, **Preset-Bundle**
- **Mehrere Tunnel gleichzeitig** (App A → Tunnel 1, App B → Tunnel 2, Rest direkt)
- **DNS-Upstream pro Route** (z. B. direkt → lokales Pi-hole, Tunnel → AdGuard Home am Tunnelende)
- **Fail-closed** in jeder Lage (Absturz, Boot, Tunnel weg)
- Austauschbare Frontends über eine stabile API
- Keine Telemetrie, keine Cloud, keine Accounts

### Nicht-Ziele

- Anonymisierung (kein Tor-Ersatz, kein Schutz vor Browser-Fingerprinting)
- VPN-Anbieter-Integration / Server-Marktplatz
- Schutz vor einem kompromittierten Root-Account auf dem eigenen Rechner

---

## 2. Abgrenzung

| Projekt | Was es kann | Was fehlt / Warum nicht einfach das |
|---|---|---|
| **WireSock** (Windows) | App-Split, IP-Ausnahmen, Backup-Tunnel | Closed Source, proprietärer Kernel-Treiber, nur Windows |
| **Mullvad-App** | App-Split (Linux via cgroups) | Nur Mullvad-Server, keine Domain-Regeln, kein DNS pro Route |
| **Rethink DNS / firestack** | Firewall, DNS, Multi-WireGuard, App-Regeln | Nur Android; Userspace-Netstack (langsamer auf Desktop) |
| **OpenSnitch** | App-Firewall Linux | Kein Routing, kein WireGuard |
| **wireguird** | GTK-GUI für wg-quick | Nur Tunnel an/aus, GUI läuft als root |

`firestack` (MPL-2.0) ist ein Kandidat als **Bibliothek für den DNS-Resolver-Teil** (DoH/DoT/ODoH/DNSCrypt). MPL-2.0 ist mit Apache-2.0 kompatibel; geänderte firestack-Dateien bleiben MPL.

---

## 3. Architektur

```
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│    CLI     │ │  Web-UI    │ │  Tauri /   │ │  Android-  │
│  (wsctl)   │ │ (localhost)│ │  Flutter   │ │    App     │
└─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
      └──── HTTP+JSON über Unix-Socket (polkit) ────┘
┌──────────────────────────────────────────────────────────┐
│ CORE (Go, plattformneutral)                              │
│  • Config & Profile        • Regel-Engine (Compiler)     │
│  • Tunnel-Manager          • DNS-Proxy (pro Route)       │
│  • State/Health/Killswitch • Event-Bus, Leak-Selbsttest  │
└─────┬───────────────────────┬────────────────────────┬───┘
      │      Backend-Interface (Enforcer + Tunnel)      │
┌─────┴──────────┐  ┌─────────┴────────┐  ┌────────────┴─────┐
│ Linux          │  │ Android          │  │ Windows          │
│ nftables,      │  │ VpnService,      │  │ WFP,             │
│ cgroup v2,     │  │ wireguard-go     │  │ wireguard-nt     │
│ ip rule, Kernel│  │ (gomobile)       │  │                  │
│ WireGuard      │  │                  │  │                  │
└────────────────┘  └──────────────────┘  └──────────────────┘
```

### Prozesse (Linux)

| Prozess | Rechte | Aufgabe |
|---|---|---|
| `shuntd` | systemd-Service, nur `CAP_NET_ADMIN` (+`CAP_NET_BIND_SERVICE`), gehärtet | Tunnel, nftables, Routing, DNS-Proxy, API |
| `shunt` (CLI) | User | API-Client, `shunt run --via X -- app` |
| `shunt-ui` | User | Lokale Web-UI, spricht nur mit dem Socket |

**Grundregel:** Keine Oberfläche läuft jemals mit Root-Rechten.

### Backend-Interface (Skizze)

```go
type Backend interface {
    TunnelUp(ctx context.Context, t TunnelSpec) (TunnelHandle, error)
    TunnelDown(ctx context.Context, h TunnelHandle) error
    Apply(ctx context.Context, plan CompiledPlan) error   // atomar!
    DomainSetAdd(target RouteID, ips []netip.Addr, ttl time.Duration) error
    LaunchInRoute(ctx context.Context, route RouteID, cmd []string) error
    Lockdown(ctx context.Context, on bool) error
    Capabilities() BackendCaps // was kann die Plattform? (UI blendet aus)
}
```

Die Regel-Engine kompiliert die Config in einen plattformneutralen `CompiledPlan`; das Backend übersetzt ihn in native Mechanismen. **`Apply` ist atomar** (nftables-Transaktion), es gibt nie einen halb angewendeten Zustand.

### Technik-Stack (alles permissiv lizenziert)

- `golang.zx2c4.com/wireguard/wgctrl` – Kernel-WG konfigurieren
- `github.com/vishvananda/netlink` – Interfaces, Routen, ip rules
- `nft -f -` – Ruleset als Text, eine atomare Transaktion pro Apply (lesbar, per Golden-File testbar; `google/nftables` kann `socket cgroupv2` nur umständlich)
- `github.com/miekg/dns` – DNS-Proxy (ggf. Teile aus firestack)
- `github.com/coreos/go-systemd` – Scopes/Slices über D-Bus
- HTTP+JSON über Unix-Socket – API (jedes Frontend inkl. Tauri/Flutter/curl ohne Codegen; Peer-PID per `SO_PEERCRED`)
- `BurntSushi/toml` – Config

---

## 4. Regel-Modell

### Bausteine

- **Route** (Ziel): `direct`, `block`, `tunnel:<name>`
- **Selektor**: `app`, `cidr`, `domain`, `port`, `asn`, `list`, `preset`
- **Regel**: Selektor(en) → Route, optional `killswitch`, `lan` (allow/deny), `dns` (Override)

### Auswertung

1. Regeln haben eine explizite Reihenfolge, **first match wins**.
2. Mehrere Selektoren in einer Regel = UND-Verknüpfung.
3. Empfohlene Default-Reihenfolge (UI sortiert so vor):
   `block` → `domain` / `cidr` / `port` → `app` → Default-Route.
   *Begründung:* Spezifisches (diese Seite) schlägt Allgemeines (diese App).
4. Ohne Treffer greift die **Default-Route** des aktiven Profils.

### Beispiel-Config (TOML)

```toml
[profile.zuhause]
default_route = "direct"
dns.direct    = "pihole"

[profile.unterwegs]
default_route = "tunnel:home"      # alles nach Hause
killswitch    = true
net_hygiene   = { random_mac = true, hide_dhcp_hostname = true }
match.ssid_not = ["MeinWLAN"]       # automatische Umschaltung

[dns.upstream.pihole]
addr = "192.168.1.2:53"

[dns.upstream.adguard-vps]
addr  = "https://10.8.0.1/dns-query"  # DoH, über den Tunnel erreichbar
route = "tunnel:vps"                  # MUSS über diese Route laufen

[tunnel.vps]
config = "/etc/shunt/tunnels/vps.conf"   # wg-quick-kompatibel, 0600
dns    = "adguard-vps"

[tunnel.home]
config = "/etc/shunt/tunnels/home.conf"
dns    = "pihole"

[[rule]]
name  = "Torrent nur über VPS, sonst gar nicht"
app   = ["flatpak:org.qbittorrent.qBittorrent"]
route = "tunnel:vps"
killswitch = true
lan   = "deny"

[[rule]]
name   = "Streaming direkt"
preset = ["streaming/netflix"]
route  = "direct"

[[rule]]
name   = "Firefox über VPS"
app    = ["desktop:org.mozilla.firefox", "exe:/usr/lib/firefox/firefox"]
route  = "tunnel:vps"

[[rule]]
name = "SSH immer direkt"
port = ["tcp/22"]
route = "direct"
```

---

## 5. DNS-Design

### Grundprinzip

> **Was durch einen Tunnel geht, wird durch diesen Tunnel aufgelöst.**
> Das ist keine Option, die Engine erzwingt es. (Sonst fragt z. B. Unbound am Pi-hole die Root-Server mit der Heim-IP und der Provider sieht's.)

### Ablauf

1. Jede Route bekommt einen **eigenen Listener** des DNS-Proxys (z. B. `127.0.77.1:53` = direct, `127.0.77.2:53` = tunnel:vps …).
2. nftables leitet DNS-Anfragen per **DNAT pro cgroup/Route** auf den passenden Listener um. Der Proxy weiß damit *ohne Raten*, aus welcher Route die Anfrage stammt.
3. Proxy prüft **Domain-Regeln**:
   - Treffer → Upstream der Ziel-Route der Domain-Regel verwenden; aufgelöste IPs (A/AAAA, CNAME-Kette folgen) mit TTL in das nft-Set der Ziel-Route schreiben.
   - kein Treffer → Upstream der Route des Listeners.
4. Antwort erst zurückgeben, **nachdem** die IPs im Set stehen (sonst Race: erstes Paket nimmt die falsche Route).
5. Der Proxy selbst erreicht Upstreams über die passende Route (eigene fwmark pro Upstream-Socket).

### Upstream-Typen

Plain DNS (UDP/TCP), DoT, DoH, DNSCrypt, ODoH (via firestack, optional).

### Durchsetzung (Pflicht)

- Ausgehend `udp/tcp 53` und `tcp 853` von allen außer `shuntd` → DNAT auf Proxy bzw. Drop.
- Blockliste bekannter DoH-Endpunkte (pflegbar) + Canary-Domain `use-application-dns.net` → NXDOMAIN (Firefox schaltet DoH ab).
- UI zeigt deutlich: *„Domain-Regeln greifen nicht für Apps mit eigenem DoH.“*

### Hygiene

- EDNS Client Subnet entfernen
- EDNS-Padding (RFC 7830/8467) bei verschlüsselten Upstreams
- DNSSEC-Validierung optional
- Query-Logs nur im RAM, standardmäßig aus

### Bekannte Grenzen

- **CDN-Sharing:** Domain-Regeln routen IPs, nicht Domains. Andere Seiten auf derselben CDN-IP nehmen dieselbe Route. Wird dokumentiert, nicht „gefixt“.
- **Hardcodierte IPs / eigene Resolver** in Apps umgehen Domain-Regeln (App- oder CIDR-Regeln greifen weiterhin).
- **nss-resolve umgeht Port 53.** Auf Pop!_OS verifiziert: `hosts: files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns myhostname`. glibc-Apps (`getaddrinfo`) fragen systemd-resolved damit per **Varlink**, nicht über `127.0.0.53:53` → kein DNAT möglich, resolved sieht nur sich selbst als Absender.
  **Lösung:** Der Installer entfernt `resolve [!UNAVAIL=return]` aus `nsswitch.conf` (Backup, sauberes Rückgängigmachen bei Deinstallation). Dann greift `dns` → `/etc/resolv.conf` → `127.0.0.53` → per-cgroup-DNAT auf unsere Listener. `shuntd` prüft beim Start und verweigert DNS-Regeln (laut, in der UI), solange `resolve` aktiv ist.
  Apps, die resolved direkt über D-Bus/Varlink fragen (selten), bleiben eine dokumentierte Lücke. Den Varlink-Socket pro App zu sperren ginge nur per LSM (AppArmor/Landlock) – Roadmap, nicht MVP.
- **mDNS (`.local`)** geht per Multicast direkt ins LAN – bewusst so, LAN-Leak only. Mit `lan = "deny"` für die App mitgesperrt.

---

## 6. Linux-Backend (Pop!_OS)

### 6.1 App-Zuordnung via cgroup v2

**Umgesetzt (P1):** `shuntd` besitzt einen eigenen cgroup-Teilbaum (systemd `Delegate=yes`, Prinzip wie bei Mullvad):

```
system.slice/shuntd.service/
├── daemon/                 ← shuntd selbst (eigener Traffic nie klassifiziert)
└── apps/
    ├── g/<gruppe>/         ← shunt run --group <gruppe>
    └── via/<route>/        ← shunt run --via direct|block|tunnel:<name>
```

- `shunt run --via tunnel:vps -- firefox`: Die CLI fragt `shuntd` über den Socket, der Daemon liest die PID per `SO_PEERCRED` (nie aus dem Request), schiebt *die CLI selbst* in die cgroup, danach `exec` → Firefox und alle Kinder starten bereits drin, bevor ein einziger Socket offen ist.
- Diese cgroups sind **langlebig** → stabile IDs für `socket cgroupv2` (nftables löst Pfade beim Laden der Regel auf; deshalb verworfen: flüchtige systemd-Scopes, User-Slices, die systemd wegräumt).
- Nachteil: Die App verlässt die cgroup der Desktop-Session (Ressourcen-Accounting der Session). Für einen Netzwerk-Router akzeptabel.
- **Flatpak/Snap/Desktop-Scopes (P3):** Der Daemon beobachtet systemd (D-Bus `UnitNew`) und hängt Regeln auf genau diesen Scope ein. ⚠️ COSMIC-Verhalten noch zu verifizieren.
- **`exe:`-Selektor (P3)** via Proc-Connector (`PROC_EVENT_EXEC`) + Umhängen. **Race:** Erste Pakete vor dem Umhängen könnten falsch laufen → mit Killswitch nur im „unklassifiziert = block“-Modus. Bestehende Sockets behalten ihre cgroup.

### 6.2 Markierung & Routing

```
nft table inet shunt
 ├─ chain output   (type route, hook output, priority mangle)
 │    ct mark != 0  → meta mark set ct mark ; return       # bestehende Verbindungen
 │    <kompilierte Regeln, first match wins>                # setzt meta mark
 │    meta mark != 0 → ct mark set meta mark
 ├─ chain nat_out  (type nat, hook output)                  # DNS-DNAT pro Route
 ├─ chain postrouting (type nat) oifname "wg-*" masquerade  # Quell-IP fixen nach Reroute
 ├─ chain filter_out (type filter, hook output, policy drop bei Lockdown/Killswitch)
 └─ sets: dst_<route>_v4 / _v6 (flags timeout), lan_nets, doh_block
```

- Änderung der Mark in einer `type route`-Chain löst im Kernel ein **Reroute** aus.
- ⚠️ **Lehrgeld aus P1:** Im `output`-Hook meldet `oifname` noch das Interface *vor* dem Reroute (der Hook-State wird einmal pro Hook gesetzt). Die Prüfung „Tunnel-Mark muss über das Tunnel-Interface raus“ (`leak_guard`) muss deshalb im **postrouting**-Hook sitzen – im output-Hook verwirft sie jedes korrekt umgeroutete Paket.
- Antworten auf **eingehende** Verbindungen (`ct direction reply`) werden nie klassifiziert (sonst würde z. B. ein lokaler SSH-Server bei Default-Route-Tunnel in den Tunnel antworten).
- Pro Route: eigene Routing-Tabelle + `ip rule fwmark <m> lookup <t>` (v4 **und** v6).
- **Jede Tunnel-Tabelle enthält immer `unreachable default` mit hoher Metrik.** Ist der Tunnel weg, fällt Traffic **nicht** in die Main-Tabelle durch → Killswitch ist Eigenschaft der Tabelle, nicht des Daemons.
- WireGuard-eigene UDP-Pakete: `wg set fwmark <bypass>` → Main-Tabelle (kein Routing-Loop).
- wireguard-go (Userspace-Fallback) läuft **im Daemon-Prozess** und wird direkt über `IpcSet/IpcGet` gesteuert – kein UAPI-Socket unter `/var/run/wireguard` (eine root-Steuerschnittstelle weniger; die liegen zudem netns-übergreifend im selben Verzeichnis).
- `net.ipv4.conf.all.src_valid_mark=1` (wie wg-quick), rp_filter für `wg-*` auf loose.
- **IPv6:** Tunnel ohne v6 → v6-Tabelle der Route nur `unreachable default` = v6 für diese Apps blockiert, nicht geleakt.
- `wg-quick` wird **nicht** verwendet; Configs im wg-quick-Format werden nur **importiert**.

### 6.3 Fail-closed

| Situation | Verhalten |
|---|---|
| Daemon stürzt ab | nft-Regeln & Routen bleiben im Kernel → weiter blockiert/geroutet |
| Tunnel down | `unreachable default` greift für Regeln mit Killswitch; ohne Killswitch fällt die Regel bewusst auf `direct` zurück (Opt-out, in UI rot markiert) |
| Boot | `shunt-lockdown.service` (`Before=network-pre.target`) lädt Minimal-Ruleset: Drop außer lo, DHCP, ggf. LAN. Aufgehoben, sobald `shuntd` den Plan angewendet hat |
| Config-Fehler | Alter Plan bleibt aktiv (atomare Transaktion), Fehler an UI |
| Panik-Knopf | Ein Aufruf → `filter_out` Policy drop für alles außer lo |
| Captive Portal (Hotel/ICE) | Siehe 6.5 – zeitlich begrenzter Portal-Modus, nie dauerhaftes Loch |

### 6.4 Tunnel-Watchdog (DDNS)

Kernel-WireGuard löst Endpoint-Hostnamen **nur einmal** auf. Ändert sich die IP (Zwangstrennung, DDNS), bleibt der Tunnel tot.
`shuntd` überwacht `latest-handshake` pro Peer: älter als ~150 s und Traffic wartet → Endpoint-Hostname neu auflösen (über die **direct**-Route und deren Upstream, mit DNSSEC wenn möglich) und per `wgctrl` setzen. Endpoint-Änderungen werden geloggt (Hinweis auf DNS-Manipulation).

### 6.5 Captive-Portal-Modus

Mit Killswitch / Default-Route-Tunnel kommt man in kein Portal-WLAN.
- NetworkManager-Connectivity-Check (`connectivity-check.ubuntu.com`) erkennt das Portal → `shuntd` meldet es der UI.
- Nutzer aktiviert **bewusst** den Portal-Modus: **eine** dedizierte Slice (`shunt-portal.slice`) darf für **max. 5 Minuten** direkt raus; die UI startet darin einen Wegwerf-Browser (eigenes Profil, kein Session-Sharing). Alles andere bleibt gesperrt.
- Kein globales Aufmachen, keine Ausnahme für den NetworkManager-User dauerhaft (das wäre das nächste Leck).

### 6.6 Überlappende Subnetze

Hotel-WLAN `192.168.1.0/24` vs. Homelab hinter dem Tunnel ebenfalls `192.168.1.0/24`:
- Markierter Traffic (App-/CIDR-Regel → `tunnel:home`) wird per `ip rule` **vor** der Main-Tabelle in die Tunnel-Tabelle gelenkt → gewinnt automatisch. Dafür braucht die Tunnel-Tabelle explizit die Route `192.168.1.0/24 dev wg-home`.
- Unmarkierter Traffic sieht das lokale Netz. Konflikt wird beim Verbinden erkannt und in der UI angezeigt.
- Roadmap (P5): optionales 1:1-NAT (`10.99.1.0/24` ↔ Homelab), wenn beides gleichzeitig nötig ist.

### 6.7 Härtung des Daemons

- systemd: `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`*, `PrivateTmp`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`
  (*Lesen von `/proc/<pid>` für `exe:` nötig, sonst kein Home-Zugriff.)
- Scope-/Slice-Steuerung für User-Sessions über D-Bus des User-Managers bzw. durch die CLI selbst (läuft als der User → keine Rechteausweitung).
- API: Unix-Socket `/run/shunt/api.sock`, Gruppe `shunt`; schreibende Aktionen über **polkit**.
- Keys: `/etc/shunt/tunnels/*.conf`, root:root 0600. API gibt Private Keys **nie** zurück.
- Web-UI: eigener User-Prozess, bindet nur `127.0.0.1` mit Zufallstoken, prüft `Host`/`Origin` (gegen DNS-Rebinding/CSRF).

---

## 7. Andere Plattformen (Ausblick)

| | Android | Windows | macOS |
|---|---|---|---|
| Tunnel | wireguard-go (gomobile) | wireguard-nt | wireguard-go / NE |
| App-Split | `VpnService.addAllowed/DisallowedApplication` (nativ!) | WFP-Filter auf App-ID (ALE) – aufwändig | NetworkExtension Per-App-VPN (MDM-lastig) |
| Domain-Regeln | DNS-Proxy im VpnService + Routen | WFP + Routen | NE DNS-Proxy |
| Bemerkung | Großteil existiert in Rethink → Kooperation statt Klon prüfen | „Hier wohnen Drachen“ | niedrige Priorität |

Der Core bleibt identisch; `Capabilities()` meldet, was die Plattform kann, Frontends blenden Nichtunterstütztes aus.

---

### 7.1 OpenVPN als Tunnel-Treiber (geplant)

Wunsch aus dem Bekanntenkreis. Passt ohne Architekturbruch, weil Shunt **nach Interface** routet, nicht nach Protokoll:
- `shuntd` startet `openvpn` als Kindprozess mit fester `--dev sh-<name>`, `--route-noexec` / `--route-nopull` (Routen setzt *Shunt*, nicht der Server), `--script-security 1` (keine Server-Skripte), Steuerung über das Management-Interface (Unix-Socket).
- Gepushte DNS-Server → Upstream der Route (P2).
- Killswitch, Regeln, Leak-Guard bleiben identisch (Tabelle + Mark pro Route).
- Aufwand: mittel. Erst nach P2, wenn WireGuard + DNS rund laufen.

## 8. Bedrohungsmodell

### Gegner (in scope)

1. **Fremdes Netz** (Café/Hotel-WLAN, bösartiger DHCP: TunnelVision CVE-2024-3661, TunnelCrack LocalNet/ServerIP)
2. **Internetprovider** (passiv: DNS, Metadaten)
3. **Neugierige lokale Apps** ohne Root (LAN-Scans, eigenes DNS, Umgehung)
4. **Upstream-DNS / VPN-Gegenstelle** (sieht nur, was über die jeweilige Route läuft – Minimierung via Routing)

### Hinweise für Nutzer (Doku)

- Split-Tunneling auf OS-Ebene ersetzt keine Browser-Härtung. WebRTC/ICE kann lokale IPs in den Candidates verraten, auch wenn die Pakete korrekt geroutet werden → `media.peerconnection.ice.default_address_only = true` bzw. WebRTC deaktivieren.

### Nicht in scope

Root-Malware auf dem Host, globaler passiver Angreifer, Browser-Fingerprinting, Account-Tracking.

### Pflicht-Anforderungen (nicht verhandelbar, MVP)

- [ ] Fail-closed bei Absturz, Boot, Tunnel-Ausfall (6.3)
- [ ] Policy-Routing per fwmark, nie Main-Tabellen-Fallthrough bei Killswitch
- [ ] Tests gegen TunnelVision (Option-121-Routen) & TunnelCrack
- [ ] IPv6 strikt (blockieren statt ignorieren)
- [ ] DNS-Zwang (53/853 nur über Proxy) + „durch Tunnel aufgelöst“-Regel
- [ ] Daemon-Härtung, keine Root-GUI, Keys nie über API
- [ ] Null Telemetrie, Logs nur RAM

---

## 9. Roadmap

| Phase | Inhalt |
|---|---|
| **P0** | Dieses Design, Name, Repo, Lizenz, CI-Gerüst |
| **P1 – PoC** ✅ | `shuntd` + CLI, mehrere Tunnel, App-Regeln (eigene cgroups), CIDR-/Port-Regeln, Killswitch, IPv6-Block, Lockdown-Service, Endpoint-Watchdog, Integrationstests in Netns |
| **P2 – DNS** ✅ | DNS-Proxy pro Route, Upstreams (Plain/DoT/DoH), Domain-Regeln + nft-Sets, DNS-Zwang, DoH-Blockliste |
| **P3 – Komfort** | Captive-Portal-Modus, Mehrere Tunnel, Profile (SSID-Umschaltung, MAC/Hostname-Hygiene), Port/ASN/Presets, Web-UI, Leak-Selbsttest |
| **P4 – Release** | `.deb` für Pop!_OS, signierte reproduzierbare Builds + SBOM, App-Firewall (Default-Deny/Nachfragen), LAN-Sperre pro App, Panik-Hotkey |
| **P5 – Kür** | **OpenVPN als zweiter Tunnel-Treiber** (siehe §7.1), eBPF-Backend (`cgroup/connect4/6`, `cgroup_skb`) als Alternative zu nftables-Marks, 1:1-NAT bei Subnetz-Überlappung, Multi-Hop, Rosenpass (PQ-PSK), AmneziaWG-Modus, Padding/Cover-Traffic, Android/Windows-Backends, Tauri/Flutter-UI |

---

## 10. Entscheidungen & offene Fragen

### Entschieden

- **Name:** Shunt (`shuntd`, `shunt`). Namenskollisionen (GitHub, Debian-Pakete) vor Repo-Anlage prüfen.
- **nsswitch:** `resolve` wird bei Installation entfernt (siehe 5, „Bekannte Grenzen“).
- **DNS-Bibliothek:** `miekg/dns` + eigene DoH/DoT-Clients (stdlib). firestack nur, falls ODoH/DNSCrypt gewünscht.
- **Unklassifizierte Prozesse:** Profil mit `killswitch = true` → **block** (Default-Deny). Ohne Killswitch → `default_route`.

### Offen

1. COSMIC: Startet es Apps in eigenen `app-*.scope`-Units? Bisherige Ausgabe zeigte nur `session.slice` → `systemctl --user list-units --type=scope` prüfen.
2. Wie sollen ASN-/Preset-Listen gepflegt und **verifiziert** (signiert) verteilt werden?
3. Portal-Modus: Wegwerf-Browser – Firefox-Profil oder eigener minimaler WebView?

---

## 11. Stand Phase 1 (Implementierung)

**Getestet** (Integrationstest in Netzwerk-Namespaces, 25 Prüfungen): Routing per `--via` / `--group` / CIDR+Port, Vererbung an Kindprozesse, Block-Route, Killswitch bei gelöschtem Interface und gestopptem Daemon, Default-Route-Tunnel inkl. Ausweg per `--via direct`, Bypass-Mark (Handshake), Panic-Mode, `cleanup`, Ablehnung welt-lesbarer Keys, ignoriertes `PostUp`. IPv6-Prüfungen und der Kernel-WireGuard-Pfad laufen in der GitHub-CI (der Entwicklungs-Container hat weder IPv6 noch das WG-Kernelmodul).

**Noch nicht getestet:** die systemd-Units (Härtung!) und echter Betrieb auf Pop!_OS.

**Bewusste Lücken in P1:**
- **DNS wird nicht geroutet** → Anfragen getunnelter Apps laufen über den System-Resolver (Leak). Kommt in P2.
- Killswitch ist immer an (kein Fallback auf `direct` bei Tunnel-Ausfall).
- Socket-Zugriff = volle Kontrolle (Gruppe `shunt`); polkit kommt in P4.
- LAN-Zugriff getunnelter Apps geht in den Tunnel (faktisch gesperrt).

## 12. Stand Phase 2 (DNS)

**Umgesetzt:** Proxy-Listener pro Route (`127.0.0.1:53530+n`), Umleitung *aller* Port-53-Anfragen per nftables (auch an `127.0.0.53` und beliebige Resolver-IPs, UDP und TCP), Upstreams Plain/TCP/DoT/DoH mit Route-Mark, Domain-Regeln mit nft-Sets, DoT-Sperre, DoH-Canary + bekannte DoH-Hosts → NXDOMAIN, ECS-Entfernung, `fix-nsswitch`.

**Entscheidungen beim Bauen:**
- Upstream-Adressen müssen IP-Literale sein (sonst bräuchte der Resolver einen Resolver – der leakt).
- **Zwei Sets pro Regel und Familie (a/b):** nftables kann den Timeout eines vorhandenen Elements nicht verlängern; Löschen+Neuanlegen öffnet ein Fenster, in dem Verbindungen die Default-Route nehmen. Der Proxy schreibt deshalb ins jeweils freie Set und kappt die TTL an den Client auf die Restlebensdauer → *Client-Cache lebt nie länger als der Set-Eintrag*.
- Antwort erst **nach** dem Set-Eintrag an den Client; schlägt der Eintrag fehl → SERVFAIL statt Leak.
- Domain-Regeln nur mit `port` kombinierbar (der Proxy kennt die Route der Anfrage, nicht die Gruppe).
- DoH-Upstreams werden per IP angesprochen, TLS-Name separat → keine Auflösung nötig.

**Integrationstest:** zwei Fake-DNS-Server (direkt / nur durch den Tunnel erreichbar) melden, über welchen Weg eine Anfrage kam. 42 Prüfungen, inkl. „Tunnel weg → DNS SERVFAIL“ und „Daemon gestoppt → DNS tot statt Leak“.

**Installer:** `install.sh` (Debian-Familie inkl. Kali), Release-Workflow mit SHA256SUMS, CI-Job installiert echt auf einem systemd-Runner und deinstalliert wieder.

## 13. Stand Phase 3 (Apps & Oberfläche)

**Umgesetzt:**
- **App-Regeln** (`app = [...]`): Exec-Events vom Kernel-Proc-Connector (Netlink), `/proc`-Scan als Fallback (nur im Init-Netns verfügbar) und als Sicherheitsnetz gegen verlorene Events. Explizites `shunt run` gewinnt immer.
- **Bewusste Grenze:** zwischen exec und Umhängen liegt ein Fenster (typisch < 1 ms); Sockets aus diesem Fenster behalten ihre Route. Deshalb zusätzlich:
- **Menü-Einträge** (`shunt desktop`): Kopie der .desktop-Datei im User-Verzeichnis mit `shunt run --via …` vor jedem Exec, `DBusActivatable=false` (sonst startet D-Bus die App am Exec vorbei). Race-frei, ohne root, rückbaubar.
- **Leak-Test** (`shunt leaktest` / UI): pro Route ein Probe-Prozess *in* der Route; Urteil gegen die Direkt-Route (gleiche IP → LEAK, gleicher Resolver → WARN). Kontaktiert api.ipify.org und Google-DNS – in UI und CLI offen benannt.
- **Web-UI** (`shunt ui`): läuft als User, nur 127.0.0.1, Token → HttpOnly/SameSite=Strict-Cookie, Host-/Origin-Prüfung (DNS-Rebinding/CSRF), strikte CSP, alles eingebettet (kein CDN). Später 1:1 in Tauri wiederverwendbar.

- **Starter pro Profil** (`shunt desktop clone`): zusätzlicher Menü-Eintrag, der eine eigene Instanz (z. B. Firefox `--new-instance -P sm`) über eine feste Route startet. Chromium/Brave: Profile *innerhalb* einer Instanz teilen sich den Netzwerk-Prozess → nur getrennte `--user-data-dir` lassen sich trennen.
- **`args`-Selektor** für App-Regeln (Kommandozeile enthält z. B. `-P sm`).
- **Config-Bearbeitung über API/UI**: Formular-Editor (strukturiert, Kommentare gehen verloren – so angezeigt) und Raw-Editor (behält Kommentare). Jede Änderung durchläuft dieselbe Prüfung wie `shuntd check`, wird atomar geschrieben, `.bak` bleibt, bei Fehlschlag automatisches Zurückrollen. Sicherheitsgrenzen: `[daemon]` (Socket, Gruppe, cgroup) nur in der Datei änderbar; Tunnel-Dateien nur unter `/etc/shunt/tunnels` (die API kann den root-Daemon keine beliebigen Dateien lesen lassen); Import speichert mit 0600; Private Keys verlassen den Daemon nie. Wer im Socket-Gruppe ist, darf konfigurieren – feinere Rechte (polkit) folgen in Phase 6.

**Noch offen aus Phase 3:** ASN-/Preset-Listen, Killswitch-Fallback auf `direct` (opt-out). (Profile, Captive Portal, MAC/Hostname: §15.)

## 14. Sicherheits-Review (Phase 6)

**Gefunden und behoben:**
1. **App-Regeln wirkungslos im gehärteten Dienst** (schwer): ohne `CAP_SYS_PTRACE` ist `/proc/<pid>/exe` fremder Prozesse unlesbar; der Watcher hielt Desktop-Apps für Kernel-Threads. Fix ohne neue Capability (Kernel-Thread = leere Kommandozeile, `exe:` fällt auf absolutes argv[0] zurück). Der Integrationstest läuft seitdem mit exakt den Rechten der Unit und Apps als anderem User.
2. **Ausbruch über die eigene API** (mittel): eine in den Tunnel gezwungene App konnte sich per `/v1/run` selbst auf `direct` setzen. Jetzt nur noch in dieselbe Route oder `block`, sonst polkit.
3. **PID-Wiederverwendung beim Attach** (gering): Prozess wird über Startzeit vor und nach dem Verschieben verifiziert.
4. **Zu breite Rechte der Socket-Gruppe** (mittel): Config, Reload, Tunnel, Panik-AUS brauchen jetzt root oder polkit (`org.theshunt.manage`, `auth_admin_keep`). Status, Starten, Panik-AN bleiben ohne Passwort.
5. **Absturz im Netlink-Parser** (gering, vom Fuzzer gefunden): Slice-Grenze beim Alignment; behoben, Eingabe als Regressionstest.
6. **DNS-Antworten mit Sonderadressen** in Domain-Sets (gering): `0.0.0.0`, Loopback, Link-Local, Multicast werden nie geroutet.
7. **CI-Lücke**: `! befehl` wird von `set -e` ignoriert – negative Prüfungen in der CI hätten nie Alarm geschlagen. Korrigiert.

**Gehärtet:** Capabilities auf `CAP_NET_ADMIN CAP_CHOWN` reduziert, `ProtectHome=yes`, `DevicePolicy=closed` (nur `/dev/net/tun`), `UMask=0077`, `PrivateIPC`, Header-/Idle-Timeouts und Body-Limits an der API, Panic-Recovery im DNS-Handler, Fuzzing der Parser in der CI, govulncheck in der CI, Build-Provenance (sigstore) für Releases.

**Bewusst nicht behoben, dokumentiert (SECURITY.md):** App-Routing ist keine Sandbox (Ausbruch über `systemd-run --user`, D-Bus-Aktivierung, Browser-Handover); App-Regeln haben ein Startfenster; Domain-Regeln vertrauen dem DNS ihrer Route (Warnung bei Klartext-DNS auf `direct`).

**Nicht geprüft in dieser Runde:** Seitenkanäle (Traffic-Analyse), Verhalten unter Last/DoS durch lokale Gruppenmitglieder, macOS/Windows/Android (gibt es noch nicht).

## 15. OpenVPN, Multi-Hop, Netzwerkprofile (Phasen 4/5 teilweise)

**OpenVPN-Treiber** (`driver = "openvpn"`): shuntd startet das `openvpn`-Binary selbst, als Kind im Daemon-cgroup, mit `--route-noexec --persist-tun --script-security 1 --mark <route>` und `--pull-filter ignore redirect-gateway`. openvpn legt nur das TUN-Interface an und setzt die Adresse. Routen (Tabelle der Route), Killswitch und DNS macht wie bei WireGuard Shunt. Gepushte DNS-Server landen beim DNS-Proxy der Route (Upstream „pushed“). Status kommt aus dem Log (verb 3): kein Management-Socket, keine Skripte. `--allow-recursive-routing`, weil openvpn sonst Pakete an die eigene Server-IP verwirft; Schleifen verhindern bei Shunt die Marks.
- `.ovpn`-Prüfung (`internal/ovpnconf`): alles, was Programme startet, Bibliotheken lädt, Dateien schreibt oder Rechte wechselt, wird abgelehnt (`up`, `plugin`, `script-security`, `management`, `log`, `status`, `user`, `cd`, `config`, Server-Modus …). Beim Import über API/UI sind nur Inline-Zertifikate erlaubt; die Login-Datei (`auth`) muss wie die Configs unter `/etc/shunt/tunnels` liegen, weil openvpn ihren Inhalt an den Server schickt.
- openvpn läuft mit `Pdeathsig` und Pid-Datei (Reste nach Absturz werden beendet) und startet nach Abbruch mit Backoff neu. Bei AUTH_FAILED steht der Grund im Status.

**Multi-Hop** (`via = "tunnel:<name>"`, auch nur `"<name>"`): Der äußere Tunnel bekommt die Pakete des inneren über dessen Socket-Mark (WireGuard `fwmark`, openvpn `--mark`). Die erste Regel im `route_out`-Hook lässt von shuntd gesetzte Marks stehen und schreibt sie in die Conntrack-Mark (Rückweg/rp_filter). Ist der äußere Tunnel weg, greift dessen `unreachable`-Route: der innere ist blockiert, nichts geht direkt zum inneren Server. Schleifen lehnt `check` ab. Die innere MTU wird ohne eigene Angabe auf außen − 80 gesetzt. Hostnamen des inneren Endpoints löst shuntd direkt auf (dem lokalen DNS bekannt) – bei Bedarf IP eintragen.

**Netzwerkprofile** (`[[network]]`): Erkennung über die Default-Route der main-Tabelle, die MAC des Gateways (Nachbartabelle) und die SSID (nl80211). Alle 5 s geprüft; bei Wechsel wird der Plan mit dem Profil-Default neu angewendet. SSIDs sind fälschbar, die UI warnt bei Profilen ohne Gateway-MAC, die den Schutz lockern. Unbekanntes Gateway (MAC noch nicht in der Nachbartabelle) zählt als fremdes Netz.

**Captive Portal:** `shunt captive` / Tray: ein neuer Browser-Prozess (Firefox `--no-remote --profile <tmp>`, Chromium `--user-data-dir`) in der Route `direct`, Profil wird danach gelöscht. Ein laufender Browser würde die URL übernehmen und in seiner eigenen Route öffnen – deshalb immer ein eigener Prozess. Ist `dns.direct` verschlüsselt, kann das Portal den DNS blockieren; dann vorübergehend auf Systemresolver stellen.

**Captive-Portal-Erkennung:** Nach jedem Netzwechsel (und alle 15 s, solange nicht „online“) holt shuntd `http://nmcheck.gnome.org/check_network_status.txt` – direkt, ohne Redirects zu folgen. Erwarteter Text → online; Redirect oder anderer Inhalt → Portal (Login-URL = Redirect-Ziel). Status/Tray zeigen es, die App fragt einmal pro Netz, ob der Wegwerf-Browser geöffnet werden soll. Abschaltbar (`daemon.captive_check = false`), weil der Probe-Host sieht, dass man online ist (NetworkManager fragt denselben Host meist ohnehin).

**MAC-/Hostname-Hygiene:** Installer-Option, schreibt `/etc/NetworkManager/conf.d/90-shunt-privacy.conf` (`wifi.cloned-mac-address=stable`, Scan-MAC zufällig, kein Hostname in DHCP, IPv6-Privacy). Shunt fasst die Netzwerkkarte selbst nicht an (das ist NetworkManagers Job).

**Aus dem Praxistest (Laptop, 2026-10-13):**
- *Lost Update im Formular*: Eine Änderung in der Datei wurde von einem länger offenen Formular überschrieben. Jetzt trägt `GET /v1/config` eine Version (SHA-256 der Datei); ein Speichern auf alter Basis bekommt 409, die UI lädt nach Rückfrage neu und folgt Änderungen von außen automatisch, solange nichts bearbeitet wird.
- *Import „tut nichts“*: `confirm()`/`prompt()` sind in eingebetteten WebViews nicht verlässlich. Alle Rückfragen (auch PANIC) sind jetzt ein eigener Dialog in der Seite; jeder Abbruch meldet sich. Verwaiste Tunnel-Dateien blockieren einen Neu-Import nicht mehr. `shunt import` (mit sudo) für root-only Dateien wie `/etc/wireguard/*.conf`.
- *DNS-Server durch den Tunnel nicht erreichbar*: Der Proxy führt pro Route Buch; nach 3 Fehlschlägen über ≥ 15 s gilt die Route als „DNS kaputt“: einmal geloggt (statt pro Anfrage), Warnung im Status, Tray gelb, Benachrichtigung; Erholung wird ebenso gemeldet.
- *Neustart-Knöpfe*: `POST /v1/restart` (polkit) beendet shuntd mit Code 75, systemd (`Restart=on-failure`) startet neu; der Killswitch bleibt dazwischen. Tray: „Restart service“ und „Restart service and app“.
