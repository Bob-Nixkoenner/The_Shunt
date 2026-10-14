# The Shunt für Android

Stand: 14.10.2026, erster Wurf (Branch `android`, nur lokal).

## Idee

Android gibt einer VPN-App **genau ein** TUN-Interface (`VpnService`), und es kann nur eine
VPN-App gleichzeitig aktiv sein. Mehrere Tunnel gleichzeitig gehen trotzdem – so wie bei
Rethink DNS (firestack): Das TUN wird **in der App** von einem Userspace-Netzwerkstack
(gVisor) terminiert, und jede neue Verbindung wird von der App selbst neu aufgebaut:

```
App A ─┐                         ┌─ WireGuard "laptop" (eigener gVisor-Netstack) ─► Server 1
App B ─┼─► TUN ─► gVisor-Stack ──┼─ WireGuard "sd1"    (eigener gVisor-Netstack) ─► Server 2
App C ─┘   (10.111.0.2)   │      ├─ direct: normaler Socket (Shunt ist vom eigenen VPN ausgenommen)
                          │      └─ block:  RST / kein Antwort-Datagramm
                          └─ UID der Verbindung: ConnectivityManager.getConnectionOwnerUid()
```

- **Pro App eine Route** (`direct`, `block`, `tunnel:<name>`), Rest über die Standard-Route.
- **DNS pro Route:** Die VPN meldet `10.111.0.53` als DNS-Server. Anfragen dorthin gehen zum
  DNS-Server der Route der fragenden App: Tunnel → `DNS=` aus der WireGuard-Datei (sonst
  1.1.1.1 *durch den Tunnel*), direct → `direct_dns`.
- **Fail closed:** Ein Tunnel, der nicht hochkommt, oder eine unbekannte Route blockiert –
  nichts fällt auf direct zurück.
- Die Shunt-App selbst ist per `addDisallowedApplication` ausgenommen: ihre Sockets
  (WireGuard-UDP, direct-Verbindungen, Endpoint-Auflösung) gehen ohne Schleife ins echte Netz.

## Aufbau

| Teil | Inhalt |
|---|---|
| `mobile/` (Go, `//go:build linux`) | Kern: gVisor-Stack am TUN-fd (`stack.go`), WireGuard-Tunnel mit eigenem Netstack (`wg.go`, nutzt `internal/wgconf`), API für gomobile (`mobile.go`) |
| `mobile/mobile_test.go` | End-to-End ohne Android: echter WireGuard-Server im Test, App-Seite als zweiter gVisor-Stack über ein Socketpair. Prüft Tunnel, DNS-Umleitung, block, direct, kaputten Tunnel, Live-Regelwechsel und **zwei Tunnel gleichzeitig pro App** |
| `android/` | Kotlin + Jetpack Compose: `ShuntVpnService` (VpnService, UID-Lookup), `Store` (Einstellungen als JSON), `MainActivity` (Status, Tunnels, Apps) |
| `android/build-core.sh` | baut `mobile/` mit gomobile zu `android/app/libs/shunt-core.aar` |

API zwischen Kotlin und Go (gomobile, Java-Paket `org.theshunt.mobile`):

- `Mobile.start(tunFd, configJson, platform)` → `Engine` (`stop()`, `status()` JSON, `setRules(json)`)
- `Mobile.checkWireGuard(text)` → Kurzinfo JSON oder Fehler (Import-Prüfung)
- `Platform`: `uid(proto, srcIP, srcPort, dstIP, dstPort)`, `log(msg)`

Config-JSON: `{"tunnels":[{"name":"laptop","conf":"<wg-quick>"}], "default":"tunnel:laptop",
"apps":{"10123":"direct"}, "direct_dns":"1.1.1.1"}` – die App speichert Paketnamen und setzt
beim Start die UIDs ein.

## Bauen

```sh
# einmalig: SDK unter ~/Android (siehe ~/Android/setup.sh), dazu
#   platforms;android-35, build-tools;35.0.0, ndk;27.2.12479018, Gradle 8.11
android/build-core.sh                      # Go-Kern -> app/libs/shunt-core.aar
cd android && gradle assembleDebug         # -> app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Go-Tests: `go test ./mobile/`.

## Offen / nächste Schritte

- DNS-Filter (Blocklisten aus `internal/blocklist`) in den DNS-Pfad hängen.
- Apps mit Route `direct` per `addDisallowedApplication` ganz am VPN vorbei (spart Akku);
  braucht dann einen VPN-Neustart bei Regeländerung.
- Netzwechsel (WLAN ↔ Mobil): WireGuard-Endpoints neu binden (`ConnectivityManager`-Callback).
- WLAN-Profile wie auf dem Desktop (SSID → Standard-Route).
- ICMP (Ping) wird nicht weitergeleitet.
- Export/Import der Einstellungen, Regeln vom Desktop übernehmen.
