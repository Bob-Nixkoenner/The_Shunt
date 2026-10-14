# The Shunt für Windows – Plan

Stand: 14.10.2026, Vorbereitung (Branch `android`, nur lokal). Getestet werden soll auf dem
Desktop (Windows-Host), siehe unten.

## Ansatz: derselbe Kern wie Android

Der Linux-Weg (cgroups + nftables-Marks + Kernel-WireGuard) existiert auf Windows nicht.
Die Alternativen:

| Weg | Pro | Contra |
|---|---|---|
| **WFP-Callout-Treiber** (wie WireSock) | schnell, alles im Kernel | eigener signierter Kernel-Treiber (EV-Zertifikat, Microsoft-Signatur) – für ein Hobbyprojekt unrealistisch |
| **WFP ohne Callout + Routing-Tabelle** | kein eigener Treiber | WFP kann nur erlauben/sperren, nicht pro App *umleiten* – App-Split damit nicht machbar |
| **wintun + Userspace-Stack** (wie Clash/sing-box, Rethink auf Android) | kein eigener Treiber (wintun ist von WireGuard signiert), **Kern schon fertig** (`internal/splitstack`) | Userspace kostet etwas CPU; braucht Prozess-Zuordnung pro Verbindung |

→ **wintun + `internal/splitstack`.** Das ist exakt das Android-Modell:

```
Apps ─► wintun "Shunt" (Default-Route 0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1)
          └─► gVisor-Stack (splitstack)
                ├─ App-ID = Pfad der .exe (GetExtendedTcpTable/GetExtendedUdpTable → PID → QueryFullProcessImageName)
                ├─ tunnel:<name> → WireGuard (wireguard-go, eigener Netstack pro Tunnel)
                ├─ direct        → Socket gebunden ans physische Interface (IP_UNICAST_IF)
                └─ block         → RST
```

## Was dafür noch fehlt

1. **Link-Endpoint für wintun:** `golang.zx2c4.com/wireguard/tun.CreateTUN` (nutzt wintun)
   + gVisor `link/channel`-Endpoint, zwei Goroutinen pumpen Pakete hin und her
   (`splitstack.Options.Link`).
2. **Owner (Prozess):** pro neuer Verbindung `GetExtendedTcpTable` / `GetExtendedUdpTable`
   (iphlpapi, `TCP_TABLE_OWNER_PID_ALL`) nach Quell-IP:Port durchsuchen → PID → Pfad;
   Cache, weil die Tabellen groß sind. App-ID = Pfad in Kleinbuchstaben
   (`c:\program files\mozilla firefox\firefox.exe`). In `shunt.toml` gibt es schon
   `app = [...]`-Regeln – dort Windows-Pfade bzw. Programmnamen erlauben.
3. **Ausbruch aus dem eigenen TUN:** `Options.DialDirect` setzt per `Control`-Hook
   `IP_UNICAST_IF` / `IPV6_UNICAST_IF` auf das physische Interface; WireGuards UDP-Socket
   ebenso – die Windows-`conn.Bind` von wireguard-go hat dafür
   `BindSocketToInterface` (`Options.NewBind`).
4. **DNS:** wintun-Interface bekommt `10.111.0.53` als DNS (per `netsh`/`SetInterfaceDnsSettings`),
   Interface-Metrik niedrig; DNS-Leaks über andere Interfaces mit **WFP-Sperrregeln**
   (das kann WFP ohne Treiber: Port 53 nur zum wintun erlauben) – das ist auch der
   Kill-Switch: alles außer wintun + eigener Prozess sperren.
5. **Dienst:** `shuntd.exe` als Windows-Dienst (`golang.org/x/sys/windows/svc`), Steuerung
   wie unter Linux über die vorhandene API (`internal/api`) – statt Unix-Socket ein Named
   Pipe mit ACL (nur Administratoren + Benutzer der Gruppe „Shunt“).
6. **UI:** Die Web-UI (`internal/ui`) läuft unverändert; Tray später (systray kann Windows).
7. **Installer:** zunächst ZIP + `shuntd.exe install` (registriert den Dienst, legt
   `C:\ProgramData\Shunt\shunt.toml` an); MSI später.

## Stand 14.10.2026

Schon gebaut (Branch `android`, nur lokal, **auf Windows noch nicht ausgeführt**):

- `internal/splitstack`: der gemeinsame Kern (aus `mobile/` herausgelöst), baut für
  Linux/Android/Windows/macOS. `TunLink` hängt ein beliebiges wireguard-go-`tun.Device`
  (wintun) an – getestet unter Linux mit einem simulierten TUN (`tunlink_test.go`).
- `internal/winsplit`: Prozess-Zuordnung (`GetExtendedTcpTable`/`-UdpTable` → PID →
  exe-Pfad, Tabellen-Parser mit Test) und `DialDirect` mit `IP_UNICAST_IF`.
- `cmd/shunt-win-proto`: Prototyp (Punkte 1–3), `GOOS=windows go build ./cmd/shunt-win-proto`.

## Reihenfolge (Vorschlag)

1. `cmd/shunt-win-proto` auf dem Desktop ausprobieren (gebaut, siehe oben): Firefox über
   Tunnel A, Rest über Tunnel B bzw. direkt. **Braucht Administratorrechte** und
   `wintun.dll` neben der exe.
2. Danach Dienst, DNS/WFP-Kill-Switch, API über Named Pipe, `shunt.toml`-Anbindung.

## Testen auf dem Desktop

Windows läuft dort laut Nutzer ggf. als Host. Ohne Windows-VM hier keine automatischen Tests
möglich; CI vettet `GOOS=windows` schon (inkl. `internal/splitstack`). Ein Windows-Runner in
GitHub Actions (`windows-latest`) kann wintun mit Adminrechten starten – damit ließe sich
der Prototyp auch in CI testen.
