# Plan: App-Firewall und Anbieter-Assistent

Stand 13.10.2026. Vorbereitung für die nächste Sitzung; offene Entscheidungen sind mit **❓**
markiert. Wer übernimmt (Claude Code lokal oder Cloud): erst die ❓ mit dem Nutzer klären.

---

## A. App-Firewall („unbekannte Programme fragen“)

### Ziel
Ein Programm ohne Regel, das zum ersten Mal ins Netz will, wird angehalten (Verbindung
abgelehnt, nichts geht raus), und der Nutzer bekommt eine Frage:

> **Firefox** (`/usr/lib/firefox/firefox`) will ins Internet.
> [tunnel:laptop] [tunnel:sd1] [direkt] [blockieren]  ☐ merken

„Merken“ schreibt eine App-Regel in die Config (wie heute über die UI), sonst gilt die
Entscheidung bis zum Programmende.

### Mechanik (Prototyp funktioniert ✅)
1. **Erkennen:** Der App-Watcher (proc connector) sieht jeden Programmstart. Ein Programm ohne
   passende App-Regel, gestartet **in der Nutzersitzung** (cgroup unter `user.slice`), kommt in
   eine „Wartegruppe“ `apps/ask/p<N>` – eine pro Programm (Pfad der Binary), nicht pro Prozess.
2. **Anhalten:** nft-Regel pro Wartegruppe:
   `socket cgroupv2 level L "…/apps/ask/p17" log prefix "ask:p17 " group 5301 reject`
   – TCP bekommt sofort einen Reset, UDP ein ICMP-Unreachable: das Programm wartet nicht
   ewig, es bekommt „kein Netz“.
3. **Mitbekommen:** shuntd liest NFLOG-Gruppe 5301 (Bibliothek `github.com/florianl/go-nflog/v2`).
   **Prototyp (13.10.):** im Netns mit nur `CAP_NET_ADMIN` → Paket kommt mit Prefix `ask:p1`
   und UID 65534 an. Kein ptrace, kein /proc/net-Raten nötig.
4. **Fragen:** API-Ereignis „pending“ (Programm, Pfad, UID, Zeitpunkt). Die Desktop-App
   (Tray) pollt `/v1/pending` (oder Long-Poll) → Benachrichtigung + Fenster mit Dialog.
   Ohne Desktop-App: `shunt pending` / `shunt allow <prog> --via …` im Terminal.
5. **Entscheiden:** `POST /v1/pending/<id>` {route, remember}. Prozesse der Wartegruppe
   wandern in die Ziel-Route (wie heute `run`), nft-Regel der Wartegruppe wird entfernt; bei
   „merken“ App-Regel anhängen (Config-Editor-Pfad mit Versionsprüfung).
6. Das Programm versucht es meist von selbst erneut (Browser, Messenger); sonst neu starten.

### Wer wird gefragt / was nie
- Nur Programme aus der **Nutzersitzung**. Systemdienste (NetworkManager, systemd-resolved,
  apt-Dienste, cups …) werden nie angehalten – sonst ist das System kaputt.
- Nie: shuntd selbst, openvpn von shuntd, Programme, die schon in einer Route sind
  (`shunt run`, Menüeinträge, App-Regeln).
- Kinder erben die Gruppe des Elternprozesses, bis sie selbst ein neues Programm starten
  (Shell → curl wird separat gefragt).
- Gefragt wird pro Programm einmal pro Sitzung; mehrere Anfragen desselben Programms
  zählen als eine.

### ❓ Entscheidungen für den Nutzer
1. **Standard-Modus**, wenn niemand antwortet (Desktop-App aus, Nutzer weg):
   a) blockieren, bis entschieden wird (sicher, kann nerven)
   b) nach z. B. 30 s die normale Default-Route nehmen (bequem, weniger sicher)
2. **Kommandozeile:** Sollen auch Terminal-Programme (curl, git, ssh, apt über sudo) gefragt
   werden? Vorschlag: ja, aber im Terminal selbst kommt kein Dialog → Tray-Benachrichtigung.
   Alternativ: Terminal-Programme erben die Route des Terminals ohne Frage.
3. **„Merken“** standardmäßig an oder aus?
4. **Name der Funktion** in der UI: „Ask before new apps go online“ / „App-Firewall“.
5. Modus pro Netzwerkprofil? (z. B. zu Hause aus, unterwegs „fragen“) – technisch einfach.

### Grenzen (ehrlich, kommt in SECURITY.md)
- Das allererste Paket wird abgelehnt, nicht verzögert: manche Programme zeigen kurz
  „keine Verbindung“.
- Programme, die sich über einen schon laufenden Prozess verbinden (Browser-Übergabe,
  D-Bus-Dienste), laufen über dessen Route – wie bei den App-Regeln.
- Flatpak/Snap: der Pfad ist der der Sandbox-Binary; Anzeige über `flatpak:<app-id>`
  (gibt es im Matcher schon).

### Umfang / Schritte
1. `internal/appwatch`: Modus „ask“ → unbekannte Programme in Wartegruppen (Pfad-Hash → pN).
2. `internal/nft`: dynamische Wartegruppen-Regeln (eigene Chain `ask`, inkrementell
   `nft add/delete rule` statt Gesamt-Reload).
3. `internal/askd` (neu): NFLOG-Leser, Pending-Liste, Entscheidungen, Timeout-Politik.
4. API + CLI (`shunt pending`, `shunt allow`) + Desktop-Dialog + UI-Liste „Wartende Apps“.
5. Integrationstest: Programm als nobody → Verbindung abgelehnt → pending sichtbar →
   Entscheidung → Verbindung durch Tunnel; Systemdienst wird nicht angehalten.
Aufwand: ~1 Sitzung.

---

## B. Anbieter-Assistent

### Lage (Recherche 13.10.)
- **Mullvad:** nur noch WireGuard (OpenVPN seit 15.01.2026 abgeschaltet). Hat eine öffentliche
  API: Relay-Liste ohne Login, Gerät/Schlüssel anmelden mit Kontonummer. → **voll
  automatisierbar**: Kontonummer eingeben, Land/Stadt wählen, Shunt erzeugt den Schlüssel
  lokal, meldet den Public Key an, baut den Tunnel. Privater Schlüssel verlässt den Rechner nie.
- **Proton:** WireGuard- und OpenVPN-Configs nur nach Login im Konto (mit 2FA); keine
  offizielle API für Dritte. → **geführter Import**: Link zur Download-Seite, Schritt-für-
  Schritt-Hinweise, dann Datei in Shunt ziehen (Import kann das schon, inkl. Login-Abfrage).
- **IVPN, AirVPN, Windscribe, …:** ähnlich – je nach API automatisch oder geführt.
- **Mitliefern von Configs:** geht nicht (kontogebunden); ist vom Tisch.

### Vorschlag
1. **Assistent-Seite** in Configure → „Tunnel hinzufügen“ mit Kacheln:
   *Eigene Datei* (heute) · *Mullvad (automatisch)* · *Proton (geführt)* · *weitere (geführt)*.
2. **Mullvad automatisch:** `internal/providers/mullvad`: Relay-Liste holen (cachen),
   Kontonummer → Gerät anlegen (Public Key), Adresse holen, `wgconf` schreiben, Tunnel
   importieren. Kontonummer wird **nicht** gespeichert (nur der erzeugte Schlüssel in der
   Tunnel-Datei, 0600). Serverwechsel = neuer Peer, gleicher Schlüssel.
3. **Geführt:** pro Anbieter ein kurzer Text + Link + „Datei hier ablegen“.
4. Hinweis-Kasten (wie gewünscht): „Shunt verbindet dich nur mit dem Anbieter. Was am
   Server passiert, liegt beim Anbieter – wähle einen, dem du vertraust.“

### ❓ Entscheidungen für den Nutzer
1. Welche Anbieter nutzt ihr wirklich (du, dein Bekannter)? Mullvad lohnt nur, wenn
   jemand ein Konto hat – zum Testen braucht es ein bezahltes Konto (5 €/Monat).
2. Proton: reicht geführter Import (empfohlen), oder Versuch einer inoffiziellen
   Login-Automatik (fragil, 2FA, Nutzungsbedingungen – rate ich ab)?
3. Soll die API-Kommunikation (Relay-Liste, Geräte-Anmeldung) über einen bestehenden
   Tunnel laufen dürfen (Opsec) oder direkt?

### Grenzen
- Mullvad-API ist von der Cloud-Sitzung aus nicht erreichbar → Tests mit nachgebautem
  API-Server im Netns; der echte Test braucht ein Konto beim Nutzer.

Aufwand: Assistent-Gerüst + geführte Anbieter ~½ Sitzung, Mullvad automatisch ~½ Sitzung.

---

## Reihenfolge-Vorschlag
1. App-Firewall (Kern ohne „merken“) → Test → Desktop-Dialog → „merken“.
2. Assistent-Gerüst + geführter Proton-Import.
3. Mullvad automatisch, sobald klar ist, dass jemand ein Konto hat.
