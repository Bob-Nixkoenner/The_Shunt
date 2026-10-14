# The Shunt für Android

Stand: 14.10.2026 nachmittags (Branch `android`, Worktree `~/projects/The_Shunt-android`, nur lokal).

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
| `internal/splitstack/` | plattformneutraler Kern (auch für Windows, siehe `WINDOWS.md`): gVisor-Stack, Routen pro App-ID, WireGuard-Tunnel mit eigenem Netstack (nutzt `internal/wgconf`), DNS pro Route + DNS-Filter (`internal/blocklist`), `NetworkChanged` |
| `mobile/` (Go, `//go:build linux`) | dünne gomobile-Hülle: TUN-fd → fdbased-Endpoint, UID → App-ID |
| `mobile/mobile_test.go` | End-to-End ohne Android: echter WireGuard-Server im Test, App-Seite als zweiter gVisor-Stack über ein Socketpair. Prüft Tunnel, DNS-Umleitung, block, direct, kaputten Tunnel, Live-Regelwechsel, Netzwechsel, DNS-Filter und **zwei Tunnel gleichzeitig pro App** |
| `test/android/` | `wgserver` (zwei WireGuard-Server „home“/„work“ für den Emulator) und `emulator-test.sh`: Routen pro App, DNS, DNS-Filter, WLAN aus/an – **auf Android 15 (Emulator) alles grün** |
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

Go-Tests: `go test ./mobile/ ./internal/splitstack/`. Emulator-Test (Emulator läuft,
`adb` verbunden): `GRADLE=~/Android/gradle-8.11.1/bin/gradle test/android/emulator-test.sh`.

## Offen / nächste Schritte

- Test auf einem echten Handy (eigene WireGuard-Peers nötig, nicht die des Laptops).
- DNS-Filter-Stufen pro App wie auf dem Desktop (jetzt: an/aus pro App, Listen global).
- DNS über TCP wird umgeleitet, aber nicht gefiltert.

- Apps mit Route `direct` per `addDisallowedApplication` ganz am VPN vorbei (spart Akku);
  braucht dann einen VPN-Neustart bei Regeländerung.
- WLAN-Profile wie auf dem Desktop (SSID → Standard-Route).
- ICMP (Ping) wird nicht weitergeleitet.
- Export/Import der Einstellungen, Regeln vom Desktop übernehmen.
