# bgp-router

Software für einen BGP VPS. Über ein Webinterface kündigst du eigene IPv4 und IPv6 Präfixe an und legst fest, wohin einzelne IPs oder Subnetze geroutet werden:

- **Lokal**: die IPs werden direkt auf dem VPS registriert
- **Per WireGuard** zu einem Backend (Homeserver, anderer VPS, …): dort registriert ein Agent die IPs automatisch lokal

BGP läuft nur auf dem Router (VPS). Die Backends brauchen kein BGP, nur ausgehend UDP zum VPS.

```
                Internet / Upstream (BGP)
                          │
                ┌─────────┴──────────┐
                │  VPS: bgp-router    │  BIRD2 (v4/v6 Sessions, RPKI)
                │  WebUI :8080        │  Dummy bgp0 → lokale IPs
                │  wg-bgp (Hub)       │  unreachable für nicht zugewiesene IPs
                └──┬──────────────┬──┘
          WireGuard│              │WireGuard
          ┌────────┴───┐    ┌─────┴──────┐
          │ bgp-agent   │    │ bgp-agent   │  IPs lokal registriert,
          │ Backend A   │    │ Backend B   │  Antworten per Policy Routing
          └─────────────┘    └─────────────┘  zurück durch den Tunnel
```

## Bestandteile

| Programm | Läuft auf | Aufgabe |
|---|---|---|
| `bgp-router` | BGP VPS | Webinterface, erzeugt die BIRD2 Konfiguration, WireGuard Hub, Kernel Routen, lokale IPs, verteilt Updates |
| `bgp-agent` | jedem Backend | holt seine Konfiguration vom Router, baut den Tunnel auf, registriert die IPs lokal, Policy Routing, Selbst-Update |

Beide sind statische Go Binaries ohne externe Abhängigkeiten. Auf dem System werden nur `iproute2`, `wireguard-tools` und auf dem VPS `bird2` benötigt.

## Installation auf dem VPS

```bash
# neuestes GitHub Release
curl -fsSL https://raw.githubusercontent.com/TinyBrickBoy/router/main/scripts/install-router.sh | sudo bash

# oder aus dem Quellcode
make dist
sudo ./scripts/install-router.sh ./dist
```

Das Skript installiert BIRD2 und WireGuard, richtet den systemd Dienst `bgp-router` ein und zeigt das initiale Passwort für den Benutzer `admin` an (auch in `/var/lib/bgp-router/initial-password`).

Firewall: TCP 8080 (Webinterface) und UDP 51820 (WireGuard) freigeben. Das Webinterface solltest du hinter einen TLS Reverse Proxy (z.B. Caddy) stellen oder `-tls-cert`/`-tls-key` verwenden, denn Setup Links und Sessions enthalten Geheimnisse.

## Einrichtung im Webinterface

1. **Einstellungen → Allgemein**: eigene ASN, Router ID (IPv4 des VPS), öffentliche URL
2. **Einstellungen → IPv4 / IPv6**: Familien aktivieren oder deaktivieren und die BGP Neighbors des Providers eintragen (Adresse, Remote ASN, Multihop, Quelladresse, Passwort). Beispiel Vultr: `169.254.169.254` bzw. `2001:19f0:ffff::1`, AS64515, Multihop 2
3. **Präfixe**: eigene Netze eintragen (z.B. `203.0.113.0/24`, `2001:db8:1000::/48`), per Klick ankündigen oder pausieren, RPKI Status prüfen
4. **Backends**: Backend anlegen und das angezeigte Setup Kommando auf dem Backend als root ausführen:
   ```bash
   curl -fsSL 'https://router.example.com/setup/<token>' | sudo bash
   ```
5. **Zuweisungen** (oder direkt auf der Backend Karte): IPs oder Subnetze einem Ziel zuweisen, also *Lokal (VPS)* oder einem WireGuard Tunnel. Das Ziel lässt sich jederzeit per Dropdown ändern.

Jede Änderung wird sofort angewendet, zusätzlich alle 5 Minuten zur Selbstheilung.

## Wie das Routing funktioniert

**Auf dem VPS**
- BIRD kündigt jedes aktive Präfix als `unreachable` Static Route an (`import none`, es werden keine fremden Routen übernommen)
- Im Kernel bekommt jedes Präfix eine `unreachable` Route. Nicht zugewiesene Adressen werden verworfen, statt zurück ins Internet zu laufen.
- Lokale Einzel IPs (`/32`, `/128`) kommen auf das Dummy Interface `bgp0`, größere lokale Netze werden per AnyIP (`local` Route) komplett registriert
- WireGuard Zuweisungen: Route `dev wg-bgp` plus die Netze in den `AllowedIPs` des jeweiligen Peers
- Alle verwalteten Routen tragen `proto 201` und werden exakt abgeglichen, veraltete werden entfernt

**Auf dem Backend (Agent)**
- WireGuard Tunnel zum VPS mit `PersistentKeepalive`, damit funktioniert das auch hinter NAT
- Zugewiesene IPs werden wie auf dem VPS lokal registriert (Dummy `bgp0` bzw. AnyIP)
- Policy Routing: `ip rule from <zugewiesenes Netz> lookup 51820` → Standardroute durch den Tunnel. Antworten und ausgehende Verbindungen dieser IPs laufen so über den VPS. Die normale Internetverbindung des Backends bleibt unverändert.
- `rp_filter` wird für den Tunnel gelockert
- Die letzte Konfiguration wird zwischengespeichert. Nach einem Neustart ohne Router Verbindung kommt der Tunnel trotzdem hoch.

`bgp-agent down` entfernt Tunnel, Adressen, Routen und Rules wieder.

## RPKI

- **Präfixe → RPKI prüfen**: fragt über RIPEstat ab, ob für jedes Präfix mit deiner ASN ein gültiger ROA existiert (valid, invalid oder unknown, inklusive der ROAs im Tooltip)
- **Einstellungen → RPKI**: optional einen RTR Validator eintragen (Routinator, StayRTR, rpki-client). BIRD kündigt dann Präfixe, die für deine ASN RPKI invalid wären, automatisch nicht an.

## Login mit OpenID Connect

Unter **Einstellungen → OpenID Connect Login** einen OIDC Provider eintragen (Keycloak, Authentik, Authelia, Zitadel, Google, Microsoft Entra …):

1. Beim Provider einen vertraulichen Client anlegen, als Redirect URI die im Webinterface angezeigte URL (`https://<deine-url>/auth/callback`)
2. Issuer URL, Client ID und Client Secret eintragen
3. Erlaubte Benutzer (E-Mail, Benutzername oder `sub`) und/oder Gruppen (`groups` Claim) festlegen. Ohne Freigabe kommt niemand rein.
4. Optional den Passwort Login deaktivieren

Verwendet wird der Authorization Code Flow mit PKCE, State und Nonce. Das ID Token wird direkt per TLS vom Token Endpoint geholt und `iss`, `aud`, `azp`, `exp` und `nonce` werden geprüft.

**Notfallzugang**: `sudo bgp-router passwd && sudo systemctl restart bgp-router` setzt ein neues Passwort und aktiviert den Passwort Login wieder.

## Updates ohne Downtime

Unter **Updates** im Webinterface:

- **Neuestes GitHub Release installieren**: lädt alle Binaries des letzten Releases (geprüft gegen `SHA256SUMS`)
- **Binaries hochladen**: Dateien aus `make dist` (`bgp-router-linux-<arch>`, `bgp-agent-linux-<arch>`)
- **Agents aktualisieren**: einzeln, alle oder automatisch. Der Agent lädt das neue Binary beim nächsten Sync (max. 30s).
- **Rollback** auf die vorherige Router Version

Ablauf: SHA256 prüfen → Selbsttest (`<binary> version`) → atomar ersetzen (Backup `*.bak`) → Prozess ersetzt sich per `execve` selbst. Die PID bleibt gleich, systemd merkt nichts. Der Router gibt dabei seinen offenen TCP Socket an den neuen Prozess weiter, sodass keine Anfrage verloren geht. BGP Sessions (BIRD), WireGuard Tunnel und Routen liegen im Kernel bzw. in BIRD und laufen während des Updates einfach weiter.

Neues Release bauen: Tag pushen (`git tag v1.2.0 && git push --tags`). Die GitHub Action baut dann alle Architekturen und hängt sie samt `SHA256SUMS` an das Release.

## Kommandozeile

```
bgp-router run   [-listen :8080] [-state /var/lib/bgp-router/state.json] [-dist /var/lib/bgp-router/dist] [-tls-cert f -tls-key f] [-dry-run]
bgp-router passwd [-state …]
bgp-router version

bgp-agent run  [-config /etc/bgp-agent/config.json] [-dry-run]
bgp-agent once [-config …]     # einmal synchronisieren
bgp-agent down [-config …]     # alles entfernen
bgp-agent version
```

Mit `-dry-run` werden alle Systembefehle nur protokolliert, praktisch zum Ausprobieren ohne root.

## Hinweise

- IPv4 Präfixe müssen mindestens `/24`, IPv6 mindestens `/48` groß sein, sonst filtern die meisten Upstreams sie
- Wird IPv6 Forwarding aktiviert, ignoriert Linux Router Advertisements. Bezieht dein VPS seine IPv6 Standardroute per RA, setze `net.ipv6.conf.<iface>.accept_ra=2` oder konfiguriere die Route statisch.
- Der Dummy Interface Name, die WireGuard Parameter und die Tunnelnetze (Standard `10.200.0.0/24`, `fd00:200::/64`) sind in den Einstellungen änderbar

## Entwicklung

```bash
make test    # go vet + Tests
make build   # bin/bgp-router, bin/bgp-agent
make dist    # alle Architekturen + SHA256SUMS
go run ./cmd/bgp-router run -dry-run -state ./dev/state.json -dist ./dist -listen 127.0.0.1:8080
```
