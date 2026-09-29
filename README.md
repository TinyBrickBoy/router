# bgp-router

Software for a BGP VPS. Through a web interface you announce your own IPv4 and IPv6 prefixes and decide where individual IPs or subnets are routed:

- **Local**: the IPs are configured directly on the VPS
- **Via WireGuard** to a backend (home server, another VPS, …): an agent there configures the IPs locally and automatically

BGP only runs on the router (VPS). Backends need no BGP, just outgoing UDP to the VPS.

```
                Internet / upstream (BGP)
                          │
                ┌─────────┴───────────┐
                │  VPS: bgp-router    │  BIRD2 (v4/v6 sessions, RPKI)
                │  web UI https :8080 │  dummy bgp0 → local IPs
                │  wg-bgp (hub)       │  unreachable for unassigned IPs
                └──┬──────────────┬───┘
          WireGuard│              │WireGuard
          ┌────────┴────┐    ┌────┴────────┐
          │ bgp-agent   │    │ bgp-agent   │  IPs configured locally,
          │ backend A   │    │ backend B   │  replies go back through the
          └─────────────┘    └─────────────┘  tunnel via policy routing
```

## Components

| Program | Runs on | Purpose |
|---|---|---|
| `bgp-router` | BGP VPS | web interface, generates the BIRD2 config, WireGuard hub, kernel routes, local IPs, monitoring and notifications, distributes updates |
| `bgp-agent` | every backend | fetches its config from the router, sets up the tunnel, configures the IPs locally, policy routing, self update |

Both are static Go binaries without external dependencies. The system only needs `iproute2`, `wireguard-tools` and, on the VPS, `bird2`.

## Installation on the VPS

A single command on the VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/TinyBrickBoy/router/main/scripts/install-router.sh | sudo bash
```

The script uses the latest GitHub release. If there is none yet, it downloads Go temporarily and builds everything from source. It installs BIRD2 and WireGuard, sets up the systemd service `bgp-router` and prints the address, the initial password for `admin` (stored in `/var/lib/bgp-router/initial-password`) and the certificate fingerprint.

If you already cloned the repo and have Go installed: `make dist && sudo ./scripts/install-router.sh ./dist`

Firewall: open TCP 8080 (web interface) and UDP 51820 (WireGuard).

If the backends reach the WireGuard port through another address, e.g. a port forwarding or proxy on a different server, set the public IP or hostname and the public port under **Einstellungen → WireGuard** (`Endpoint`, `Öffentlicher Port`). Otherwise the agents use the host of the router URL and the listen port.

### HTTPS

By default the web interface uses **HTTPS with a self-signed certificate** (`https://<vps-ip>:8080`), so the browser warns once. Compare the fingerprint with the installer output first. The setup script and the agents **pin the public key** of this certificate, so their connection to the router is protected against man-in-the-middle attacks even without a domain.

Alternatives:
- your own certificate from a CA: `-tls-cert /path/fullchain.pem -tls-key /path/privkey.pem`
- behind an HTTPS reverse proxy (e.g. Caddy): `-http -listen 127.0.0.1:8080` and set the public URL under settings to `https://…`

If the public URL points to a reverse proxy with a certificate that is valid for public CAs while the router itself runs with its self-signed certificate, the router detects this and the setup command verifies against the CA instead of pinning the router's own key.

Agents only update themselves over HTTPS. Over plain HTTP an attacker on the network could otherwise inject a manipulated binary that runs as root.

## Setup in the web interface

1. **Einstellungen → Allgemein** (settings → general): your ASN, router ID (IPv4 of the VPS), public URL
2. **Einstellungen → IPv4 / IPv6**: enable or disable the address families and add the provider's BGP neighbors (address, remote ASN, multihop, source address, password). Example Vultr: `169.254.169.254` or `2001:19f0:ffff::1`, AS64515, multihop 2
3. **Präfixe** (prefixes): add your networks (e.g. `203.0.113.0/24`, `2001:db8:1000::/48`), announce or pause them with one click, check the RPKI status, optionally set traffic engineering
4. **Backends**: create a backend and run the displayed setup command on it as root:
   ```bash
   curl -fsSL 'https://router.example.com/setup/<token>' | sudo bash
   ```
   The command contains the backend's secret token. It is hidden while the agent is online and is only shown to admins.
5. **Zuweisungen** (assignments, or directly on the backend card): assign IPs or subnets to a target, either *Lokal (VPS)* or a WireGuard tunnel. The target can be changed at any time with the dropdown.

Neighbors, prefixes, assignments and backend names can be edited in place. Every change is applied immediately and additionally every 5 minutes for self healing.

## How routing works

**On the VPS**
- BIRD announces every active prefix as an `unreachable` static route (`import none`, no foreign routes are accepted)
- In the kernel every prefix gets an `unreachable` route. Unassigned addresses are dropped instead of being sent back to the internet.
- Local single IPs (`/32`, `/128`) go onto the dummy interface `bgp0`, larger local networks are configured entirely via AnyIP (`local` route)
- WireGuard assignments: route `dev wg-bgp` plus the networks in the `AllowedIPs` of the respective peer
- All managed routes carry `proto 201` and are reconciled exactly, stale ones are removed

**On the backend (agent)**
- WireGuard tunnel to the VPS with `PersistentKeepalive`, so it also works behind NAT
- Assigned IPs are configured locally just like on the VPS (dummy `bgp0` or AnyIP)
- Policy routing: `ip rule from <assigned network> lookup 51820` → default route through the tunnel. Replies and outgoing connections of these IPs therefore go through the VPS. The backend's normal internet connection stays unchanged.
- `rp_filter` is relaxed for the tunnel
- The last config is cached. After a reboot without a connection to the router the tunnel still comes up.

`bgp-agent down` removes tunnel, addresses, routes and rules again.

The backend cards show whether the tunnel is up, the latest WireGuard handshake, the peer endpoint and the received and sent traffic (read from `wg show` on the router).

## Traffic engineering

Per prefix you can set under **Präfixe**:

- **Prepend** (0 to 10): your ASN is prepended that many additional times, making the path less attractive, e.g. for a backup upstream
- **Communities**: standard (`64515:100`) or large (`4200000000:1:2`) BGP communities. Upstreams use them for blackholing, prepending towards certain peers, regions and more, see their documentation.

As soon as a prefix of an address family uses one of these options, BIRD gets an export filter for that family which keeps the RPKI check and sets the attributes per prefix.

## RPKI

- **Präfixe → RPKI prüfen** (check RPKI): asks RIPEstat whether a valid ROA exists for every prefix with your ASN (valid, invalid or unknown, including the ROAs in the tooltip)
- **Einstellungen → RPKI**: optionally add an RTR validator (Routinator, StayRTR, rpki-client). BIRD then automatically stops announcing prefixes that would be RPKI invalid for your ASN.

## Users and roles

Besides the main user (`admin`, always an admin and not deletable) you can create more users under **Einstellungen → Benutzer** (settings → users):

- **admin**: may change everything
- **viewer**: may see everything except secrets (setup commands, tokens, webhook URLs), but cannot change anything except their own password

Sessions are bound to the user. Logging out or changing the password ends all sessions of that user.

## Login with OpenID Connect

Under **Einstellungen → OpenID Connect Login** add an OIDC provider (Keycloak, Authentik, Authelia, Zitadel, Google, Microsoft Entra …):

1. Create a confidential client at the provider, with the URL shown in the web interface as redirect URI (`https://<your-url>/auth/callback`)
2. Enter issuer URL, client ID and client secret
3. Define allowed users (e-mail, username or `sub`) and/or groups (`groups` claim). Additionally you can define read-only users and groups, who log in as viewers. Nobody gets in without being allowed.
4. Optionally disable the password login

The authorization code flow with PKCE, state and nonce is used. The ID token is fetched directly over TLS from the token endpoint and `iss`, `aud`, `azp`, `exp` and `nonce` are verified.

**Emergency access**: `sudo bgp-router passwd && sudo systemctl restart bgp-router` sets a new password for the main user and enables the password login again. `-user <name>` does the same for another local user.

## Audit log

**Protokoll** (log) shows logins, logouts, denied requests, newly registered backends and every change made in the web interface, with time, user, IP, result and the submitted values. Passwords, tokens, secrets and webhook URLs are never recorded. The log is stored as JSON lines in `/var/lib/bgp-router/audit.log` and rotated at 5 MB.

## Notifications

Under **Einstellungen → Benachrichtigungen** (settings → notifications) the router reports problems and their recovery:

- a BGP session that is down for more than a minute
- a backend that goes offline or comes back
- an announced prefix that becomes RPKI invalid (checked every 6 hours via RIPEstat)

Channels: Discord webhook, a generic webhook (JSON POST with `event`, `title`, `message`, `problem`, `router`, `time`, `text`) and e-mail via SMTP (port 587 with STARTTLS or 465 with TLS; the password is never sent in plain text). Each event type can be switched off, and a test message can be sent.

## Monitoring with Prometheus

Under **Einstellungen → Prometheus Metrics** admins generate a token that enables `/metrics`. Prometheus sends it as bearer token:

```yaml
scrape_configs:
  - job_name: bgp-router
    scheme: https
    authorization:
      credentials: "<token>"
    static_configs:
      - targets: ["router.example.com"]
```

Metrics include BGP session state, announced prefixes and their RPKI result, apply status, backend online state and last seen time, pending agent updates and WireGuard handshake and traffic per backend (`bgp_router_*`). Without a token the endpoint is disabled.

## Backup and restore

Under **Einstellungen → Backup und Wiederherstellung** (settings → backup and restore) admins download the complete configuration including users, keys, tokens and the self-signed TLS certificate. The file is encrypted with AES-256-GCM, the key is derived from a passphrase of at least 12 characters with PBKDF2 (600,000 iterations). Without the passphrase the backup cannot be recovered.

Restoring replaces the whole configuration and applies it. Because the certificate is part of the backup, a router can move to a new VPS without setting up the backends again: their pinned key stays valid. If the certificate changes, the router restarts without interruption. Afterwards you log in with the credentials from the backup.

## Updates without downtime

Under **Updates** in the web interface:

- **Install the latest GitHub release**: downloads all binaries of the latest release (verified against `SHA256SUMS`)
- **Upload binaries**: files from `make dist` (`bgp-router-linux-<arch>`, `bgp-agent-linux-<arch>`)
- **Update agents**: individually, all at once or automatically. The agent downloads the new binary on its next sync (max. 30 s).
- **Rollback** to the previous router version

Process: verify SHA256 → self test (`<binary> version`) → replace atomically (backup `*.bak`) → the process replaces itself via `execve`. The PID stays the same, systemd does not notice anything. The router hands its open TCP socket to the new process, so no request is lost. BGP sessions (BIRD), WireGuard tunnels and routes live in the kernel or in BIRD and simply keep running during the update. The agents' online status is saved to `seen.json`, so it survives updates and restarts.

Building a new release: push a tag (`git tag v1.2.0 && git push --tags`). The GitHub Action then builds all architectures and attaches them together with `SHA256SUMS` to the release.

## Command line

```
bgp-router run   [-listen :8080] [-state /var/lib/bgp-router/state.json] [-dist /var/lib/bgp-router/dist]
                 [-tls-cert f -tls-key f | -http] [-dry-run]
bgp-router passwd [-state …] [-user name]
bgp-router version

bgp-agent run  [-config /etc/bgp-agent/config.json] [-dry-run]
bgp-agent once [-config …]     # sync once
bgp-agent down [-config …]     # remove everything
bgp-agent version
```

With `-dry-run` all system commands are only logged, handy for trying things out without root.

## Security

- HTTPS by default, public key pinning for the setup script and agents, self updates only over TLS with SHA256 verification
- Login: PBKDF2 password hashes, lockout after 10 failed attempts per IP for 15 minutes, optional OpenID Connect
- Roles: viewers are read-only, enforced by the server, and never see secrets
- Sessions: signed cookies (`HttpOnly`, `Secure`, `SameSite=Strict`) bound to the user. Logging out invalidates all of that user's sessions, and so does a password change.
- CSRF tokens for all actions, strict content security policy without inline JavaScript, `X-Frame-Options: DENY`
- Audit log of all changes, without secrets
- Input is validated: no control characters in configs, no default route or private networks as prefix. The agent also validates all values from the router before applying them as root.
- State, keys and tokens live in `/var/lib/bgp-router` (readable by root only), the initial password never appears in the log
- Backups are encrypted and authenticated (AES-256-GCM)

## Notes

- IPv4 prefixes must be at least `/24`, IPv6 at least `/48`, otherwise most upstreams filter them
- When IPv6 forwarding is enabled, Linux ignores router advertisements. If your VPS gets its IPv6 default route via RA, set `net.ipv6.conf.<iface>.accept_ra=2` or configure the route statically.
- The dummy interface name, the WireGuard parameters and the tunnel networks (default `10.200.0.0/24`, `fd00:200::/64`) can be changed in the settings

## Development

```bash
make test    # go vet + tests
make build   # bin/bgp-router, bin/bgp-agent
make dist    # all architectures + SHA256SUMS
go run ./cmd/bgp-router run -dry-run -state ./dev/state.json -dist ./dist -listen 127.0.0.1:8080   # https://127.0.0.1:8080
```

With `bird` installed, the tests also validate the generated BIRD config with `bird -p`.
