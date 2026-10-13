# The Shunt – Übergabe für Claude Code

Diese Datei ist der Einstieg für jede neue Claude-Code-Sitzung (lokal oder Cloud), die an
The Shunt weiterarbeitet. Sie wird nach jedem Arbeitsschritt aktualisiert (Abschnitt
**Fortschritt** unten). Stand und Plan stehen hier, Details in `docs/DESIGN.md` (deutsch),
`README.md`, `SECURITY.md`, `CHANGELOG.md`.

## 1. Was ist The Shunt

Split-Tunneling für Linux (Pop!_OS zuerst): pro App, IP, Port, Domain entscheiden, welcher
Verkehr durch welchen VPN-Tunnel geht. WireGuard (Kernel oder wireguard-go) und OpenVPN,
Multi-Hop (`via`), DNS pro Route, Kill-Switch auch bei Daemon-Absturz, Netzwerkprofile,
Captive-Portal-Erkennung, Desktop-App (Tray + Fenster), Web-UI. Apache-2.0, keine Telemetrie.

- Repo: https://github.com/Bob-Nixkoenner/The_Shunt
- Arbeits-Branch: `claude/wiresocket-windows-tool-cehc9y` (ist faktisch der Hauptstand; Releases
  werden von hier getaggt)
- Releases: v0.5.0 (pre), **v0.6.0** (13.10.2026, mit Binaries). Nächstes: v0.6.1.

## 2. Der Nutzer (wichtig für den Ton)

- Deutsch, duzen, kurz, ehrlich vor freundlich, schwarzer Humor ok, token-sparsam.
- Arbeitet im Baumarkt-Einzelhandel, Interesse IT-Security/Opsec. Testet auf einem
  **Pop!_OS-Laptop (COSMIC, Kernel 7.1.5)** und einer Kali-VM.
- Seine Tunnel: `laptop` (WireGuard, CT111/BluCuC, 178.254.42.23:51820, 10.7.0.10) und
  `sd1` (WireGuard, CT311/SD1 `wg1`, 146.19.42.12:51821, 10.8.0.10, Exit 185.216.213.230).
  DNS: AdGuard 192.168.222.111 ist durch `laptop` erreichbar, Pi-hole 192.168.1.2 nur direkt.
  Firefox → `laptop`, Brave → `sd1` funktioniert (verifiziert 13.10.).
- Er installiert über den Installer (siehe unten); Desktop-App läuft mit Tray.

## 3. Arbeitsweise / Regeln

- Commits mit klarer Nachricht, Trailer:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (bzw. das eigene Modell).
- Vor jedem Push: `gofmt -l .` leer, `go vet ./...`, `go test ./...`, und bei Änderungen an
  Daemon/Netz der Integrationstest (root nötig):
  `sudo bash test/integration/run.sh` (≈ 4–5 min, Netns, braucht nft, wg, openvpn, openssl, python3).
  `SHUNT_DRIVER=userspace` testet wireguard-go.
- CI (`.github/workflows/ci.yml`): unit (gofmt, vet, test, fuzz, govulncheck, Cross-Build arm64 +
  Windows-vet für portable Pakete), integration (kernel + userspace), echter Install-Job.
  Linux-only Code braucht `_linux.go` bzw. Build-Tags (Windows-vet bricht sonst).
- In Test-Skripten **kein `| grep -q`** (pipefail + SIGPIPE) → Helper `gq` benutzen.
- UI-Änderungen mit Playwright prüfen (Chromium in `/opt/pw-browsers`); Mock-Daemon-Beispiel
  im Verlauf: Python-Unix-Socket-Server, der `/v1/status`, `/v1/config` liefert.
- Tags/Releases kann die Cloud-Sitzung nicht pushen (403) → Nutzer veröffentlicht über
  GitHub → Releases (Tag `vX.Y.Z`, Target = Arbeits-Branch). `release.yml` baut dann Binaries.
- Installer-Befehl für den Nutzer:
  `curl -fsSLo install.sh https://raw.githubusercontent.com/Bob-Nixkoenner/The_Shunt/HEAD/install.sh && sudo bash install.sh`
  (`--from-source` erzwingt Bauen). Danach Tray → „Restart service and app“.

## 4. Code-Landkarte

| Pfad | Inhalt |
|---|---|
| `cmd/shuntd` | Daemon (root, systemd, `CAP_NET_ADMIN CAP_CHOWN`): run, check, cleanup, lockdown, fix-nsswitch |
| `cmd/shunt` | CLI: run, status, which, import, captive, restart, ui, leaktest, desktop, panic |
| `cmd/shunt-desktop` | Tray (fyne systray) + GTK/WebKitGTK-4.1-Fenster (cgo, `window.go`) |
| `internal/daemon` | Prepare/Reload, API-Handler, Tunnel-Sync, Watchdog, Netzwechsel, Captive, polkit (`auth.go`), Config-Editor (`configedit.go`) |
| `internal/config` | TOML-Schema + Validierung (Tunnel, Rules, `[[network]]`, `via`) |
| `internal/engine` | Plan: Routen/Marks/Tabellen/Gruppen/Regeln |
| `internal/nft` | nftables-Ruleset (Golden-File `testdata/ruleset.nft`) |
| `internal/routing` | ip rules + Tabellen (Kill-Switch = `unreachable default`) |
| `internal/tunnel` | WireGuard (`tunnel.go`, `uapi.go`) und OpenVPN-Runner (`openvpn_linux.go`) |
| `internal/ovpnconf` | .ovpn-Prüfung + `Sanitize` (Skripte auskommentieren) |
| `internal/dnsproxy` | DNS-Proxy pro Route, Upstreams, Domain-Sets, DNS-Health |
| `internal/netdetect` | SSID + Gateway-MAC (nl80211/netlink) |
| `internal/captive` | Captive-Portal-Probe |
| `internal/update` | GitHub-Update-Check (3 h) |
| `internal/desktopapp` | Tray-Logik (State, Diff→Notifications, Icon, Autostart) |
| `internal/ui` | lokaler HTTP-Server + `static/` (index.html, app.js, config.js) |
| `install.sh` | Installer/Updater/Uninstaller |
| `test/integration/run.sh` | Netns-End-to-End (WG, Multi-Hop, OpenVPN, DNS, Profile, Captive, Restart …) |

## 5. Todo / Fahrplan (Priorität von oben)

**Laufend (diese Sitzung):**
1. ✅ Installer: Netzwerk-Check vorab (20 s Timeout, Hinweis statt Hänger; bei aktivem Shunt
   Angebot „am Tunnel vorbei“ neu starten), git-Timeouts.
2. ✅ OpenVPN-Import providerfreundlich: Skriptzeilen auskommentieren statt ablehnen
   (`ovpnconf.Sanitize`), Windows-only-Optionen ignorieren (`--ignore-unknown-option`).
3. Kostenlosen OpenVPN zum Testen finden: Ergebnis bisher → **Proton VPN Free** (Konto nötig,
   OpenVPN-Zugangsdaten separat unter „OpenVPN / IKEv2 username“, Configs nur nach Login).
   VPN Gate (Uni Tsukuba, ohne Konto, ehrenamtliche Server – nicht vertrauenswürdig, nur zum
   Testen). Mullvad hat OpenVPN am 15.01.2026 abgeschaltet. **Mitliefern geht nicht**
   (Configs sind kontogebunden, Proton-Configs nur mit eigenem Login); Alternative später:
   Anbieter-Assistent (z. B. Mullvad-WireGuard per Kontonummer + API).
4. 🔶 Optik: Leak-Test als Karten ✅, Mobile-Header ✅; weiter: Configure-Seite, Tray-Texte.
   Ursprünglich: Leak-Test-Tabelle (Spalten laufen über, „BLOCKED“-Text bricht hässlich um),
   allgemeiner Feinschliff der Übersicht.
5. CHANGELOG „Unreleased“ → v0.6.1 vorbereiten; Nutzer veröffentlicht. *(Text steht, wartet auf Veröffentlichung)*
6. ✅ `allow_lan` pro Tunnel (LAN am Tunnel vorbei), Checkbox in Configure, Integrationstest.

**Als Nächstes (mit dem Nutzer, siehe `docs/PLAN-firewall-providers.md`):**
- App-Firewall („unbekannte Programme fragen“) – Entscheidungen ❓ A1–A5 klären, dann bauen.
- Anbieter-Assistent (Mullvad automatisch, Proton geführt) – ❓ B1–B3 klären.

**Danach (Roadmap, siehe DESIGN §9):**
- Echttests beim Nutzer: Multi-Hop `sd1 via laptop`, Captive im Firmen-WLAN, WLAN-Profil.
- Anbieter-Assistent (Mullvad/Proton WireGuard) statt mitgelieferter Configs.
- `.deb`-Paket, SBOM, reproduzierbare Builds.
- App-Firewall (Default-Deny/Nachfragen), LAN-Sperre pro App, Panik-Hotkey.
- Killswitch-Fallback auf `direct` (opt-out), ASN-/Preset-Listen.
- Später: eBPF-Backend, 1:1-NAT bei Subnetz-Überlappung, Rosenpass, AmneziaWG,
  Android/Windows, andere UI-Technik.

**Bekannte Grenzen / offene Fragen:**
- Ungetestet auf echter Hardware: SSID-Erkennung auf echtem WLAN, Captive-Browser-Fenster,
  „Restart service and app“ unter COSMIC, echte Provider-.ovpn.
- Laufender Browser behält seine Route (neue Fenster im alten Prozess) → `shunt which`,
  UI-Warnung vorhanden.

## 6. Fortschritt (neueste oben)

- **13.10.2026, Schritt 5:** **App-Firewall** gebaut (Entscheidungen des Nutzers: 30 s →
  Default-Route; Terminal-Programme erben die Route des Terminals, `ask_terminal` schaltbar;
  „merken“ standardmäßig an; Modus pro Netzwerkprofil + Presets Paranoid/Normal/Off).
  **Bugfix Brave/Chromium unter COSMIC** (Befund aus der lokalen Sitzung): „klebende Routen“.
  Integration lokal 145/145. Offen beim Nutzer: Echttest Brave via sd1 nach Update;
  Anbieter-Assistent (Proton geführt; Mullvad erst mit Konto; API über Tunnel erlaubt,
  abschaltbar). Nebenbefund systemd-Warnung beim Dienst-Neustart („processes remain in
  cgroup“) ist gewollt (`KillMode=process`, Apps überleben den Neustart) – evtl. später Apps
  in eigene delegierte Scope-Unit verlagern.

- **13.10.2026, Schritt 4:** Nächste Bauabschnitte geplant: `docs/PLAN-firewall-providers.md`
  (App-Firewall „fragen“ + Anbieter-Assistent) mit offenen Entscheidungen (❓) für den Nutzer.
  Prototyp bestätigt: NFLOG mit nur `CAP_NET_ADMIN`, Zuordnung per Log-Prefix pro Wartegruppe,
  UID kommt mit (`github.com/florianl/go-nflog/v2`).

- **13.10.2026, Schritt 3:** Configure-Optik (Hinweistexte, Auswahlbreite), `allow_lan`
  (Routing kopiert angeschlossene private Netze in die Tunnel-Tabelle, leak_guard lässt private
  Ziele durch), Panik-Hotkey dokumentiert (Desktop-Tastenkürzel → `shunt panic on`).
  CI für 1b7328b grün, Integration lokal 134/134.

- **13.10.2026, Schritt 2:** Installer-Netzcheck, OpenVPN-Sanitize (Provider-Dateien mit
  `up`/`script-security` werden importiert, Zeilen auskommentiert; Integrationstest prüft, dass
  das Skript nicht läuft), `--ignore-unknown-option` für Windows-Optionen, Leak-Test-Karten,
  CHANGELOG „Unreleased“ ergänzt. Integration lokal 129/129.

- **13.10.2026, Cloud-Sitzung:** Übergabe-Datei angelegt. Captive-Portal-Erkennung
  (commit 46bc6c5) gepusht, CI grün. Update-Banner beim Nutzer funktioniert (Screenshot),
  Netzwerkprofil „OBI FreeWLAN“ greift. Begonnen: Installer-Netzcheck, OpenVPN-Sanitize.
