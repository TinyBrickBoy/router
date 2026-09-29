#!/usr/bin/env bash
# Installiert bgp-router auf dem BGP VPS (Debian/Ubuntu).
#
#   Neuestes GitHub Release (oder Build aus dem Quellcode, falls es noch kein Release gibt):
#     curl -fsSL https://raw.githubusercontent.com/TinyBrickBoy/router/main/scripts/install-router.sh | sudo bash
#   Lokaler Build (make dist):
#     sudo ./scripts/install-router.sh ./dist
set -euo pipefail

REPO="${REPO:-TinyBrickBoy/router}"
BRANCH="${BRANCH:-main}"
GO_VERSION="${GO_VERSION:-1.24.7}"
SRC="${1:-}"
DIST=/var/lib/bgp-router/dist

[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen." >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; GOARCH_DL=amd64 ;;
  aarch64|arm64) ARCH=arm64; GOARCH_DL=arm64 ;;
  armv7l|armv6l) ARCH=arm; GOARCH_DL=armv6l ;;
  *) echo "Nicht unterstützte Architektur $(uname -m)" >&2; exit 1 ;;
esac

# Baut alle Binaries aus dem Quellcode (Go wird temporär heruntergeladen)
build_from_source() {
  echo "==> Kein Release gefunden, baue aus dem Quellcode ($REPO@$BRANCH)"
  apt-get install -y -qq git make >/dev/null
  WORK="$(mktemp -d)"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH_DL}.tar.gz" | tar -xz -C "$WORK"
  git clone -q --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$WORK/src"
  (cd "$WORK/src" && PATH="$WORK/go/bin:$PATH" GOPATH="$WORK/gopath" GOCACHE="$WORK/cache" make dist VERSION="$(git rev-parse --short HEAD)")
  SRC="$WORK/src/dist"
}

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
  echo "==> Suche neuestes Release von $REPO"
  API="https://api.github.com/repos/$REPO/releases/latest"
  URLS="$( (curl -fsSL "$API" 2>/dev/null || true) | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/' || true)"
  if echo "$URLS" | grep -q "bgp-router-linux-$ARCH"; then
    SRC="$(mktemp -d)"
    for u in $URLS; do
      case "$u" in */bgp-*-linux-*|*/SHA256SUMS) curl -fsSL "$u" -o "$SRC/$(basename "$u")" ;; esac
    done
    (cd "$SRC" && sha256sum -c --ignore-missing SHA256SUMS)
  else
    build_from_source
  fi
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
echo "Fertig. Webinterface: https://$(hostname -I | awk '{print $1}'):8080"
if [ -f /var/lib/bgp-router/initial-password ]; then
  echo "Benutzer: admin  Passwort: $(cat /var/lib/bgp-router/initial-password)"
fi
if [ -f /var/lib/bgp-router/tls/tls.crt ]; then
  echo
  echo "Das Zertifikat ist selbst signiert, der Browser warnt deshalb einmalig."
  echo "Prüfe vor dem Akzeptieren, dass der Fingerprint übereinstimmt:"
  openssl x509 -in /var/lib/bgp-router/tls/tls.crt -noout -fingerprint -sha256 2>/dev/null || true
fi
echo
echo "Firewall: TCP 8080 (Webinterface) und UDP 51820 (WireGuard) freigeben."
