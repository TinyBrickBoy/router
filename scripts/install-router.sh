#!/usr/bin/env bash
# Installiert bgp-router auf dem BGP VPS (Debian/Ubuntu).
#
#   Neuestes GitHub Release:  curl -fsSL https://raw.githubusercontent.com/TinyBrickBoy/router/main/scripts/install-router.sh | sudo bash
#   Lokaler Build (make dist): sudo ./scripts/install-router.sh ./dist
set -euo pipefail

REPO="${REPO:-TinyBrickBoy/router}"
SRC="${1:-}"
DIST=/var/lib/bgp-router/dist

[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen." >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l) ARCH=arm ;;
  *) echo "Nicht unterstützte Architektur $(uname -m)" >&2; exit 1 ;;
esac

echo "==> Pakete installieren (bird2, wireguard-tools, iproute2)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq bird2 wireguard-tools iproute2 curl ca-certificates >/dev/null
modprobe wireguard 2>/dev/null || true
modprobe dummy 2>/dev/null || true
printf 'wireguard\ndummy\n' > /etc/modules-load.d/bgp-router.conf

install -d -m 700 /var/lib/bgp-router
install -d -m 755 "$DIST"

if [ -z "$SRC" ]; then
  echo "==> Lade neuestes Release von $REPO"
  SRC="$(mktemp -d)"
  API="https://api.github.com/repos/$REPO/releases/latest"
  URLS="$(curl -fsSL "$API" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/')"
  for u in $URLS; do
    case "$u" in */bgp-*-linux-*|*/SHA256SUMS) curl -fsSL "$u" -o "$SRC/$(basename "$u")" ;; esac
  done
  (cd "$SRC" && sha256sum -c --ignore-missing SHA256SUMS)
fi

echo "==> Binaries installieren"
for f in "$SRC"/bgp-agent-linux-* "$SRC"/bgp-router-linux-*; do
  [ -f "$f" ] && install -m 755 "$f" "$DIST/$(basename "$f")"
done
install -m 755 "$DIST/bgp-router-linux-$ARCH" /usr/local/bin/bgp-router
bgp-router version

echo "==> systemd Dienst einrichten"
cat > /etc/systemd/system/bgp-router.service <<'UNIT'
[Unit]
Description=BGP Router (WebUI, BIRD, WireGuard)
After=network-online.target bird.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bgp-router run -listen :8080 -state /var/lib/bgp-router/state.json -dist /var/lib/bgp-router/dist
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now bird >/dev/null 2>&1 || true
systemctl enable bgp-router >/dev/null
systemctl restart bgp-router
sleep 2

echo
echo "Fertig. Webinterface: http://$(hostname -I | awk '{print $1}'):8080"
if [ -f /var/lib/bgp-router/initial-password ]; then
  echo "Benutzer: admin  Passwort: $(cat /var/lib/bgp-router/initial-password)"
fi
echo "Firewall: TCP 8080 (Webinterface) und UDP 51820 (WireGuard) freigeben."
