package router

// setupScript wird für jedes Backend mit Server URL und Token befüllt.
const setupScript = `#!/usr/bin/env bash
# Setup für ein Backend, erzeugt von bgp-router
set -euo pipefail

SERVER={{shq .Server}}
TOKEN={{shq .Token}}
PIN={{shq .Pin}}
BIN=/usr/local/bin/bgp-agent
CONF_DIR=/etc/bgp-agent

if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte als root ausführen (sudo)." >&2
  exit 1
fi

# Beim selbst signierten Router Zertifikat wird dessen Public Key gepinnt (Schutz vor MITM)
CURL=(curl -fsSL)
if [ -n "$PIN" ]; then
  CURL=(curl -fsSLk --pinnedpubkey "sha256//$PIN")
fi
case "$SERVER" in
  http://*) echo "WARNUNG: Verbindung zum Router ohne TLS. Bitte im Router HTTPS verwenden." >&2 ;;
esac

echo "==> Installiere Abhängigkeiten (wireguard-tools, iproute2, curl)"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard-tools iproute2 curl ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q wireguard-tools iproute curl
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q epel-release || true
  yum install -y -q wireguard-tools iproute curl
elif command -v apk >/dev/null 2>&1; then
  apk add --quiet wireguard-tools iproute2 curl
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm --needed wireguard-tools iproute2 curl
else
  echo "Paketmanager nicht erkannt, bitte wireguard-tools und iproute2 manuell installieren." >&2
fi

modprobe wireguard 2>/dev/null || true
modprobe dummy 2>/dev/null || true

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l|arm) ARCH=arm ;;
  *) echo "Nicht unterstützte Architektur: $(uname -m)" >&2; exit 1 ;;
esac

echo "==> Lade bgp-agent ($ARCH)"
TMP="$(mktemp)"
"${CURL[@]}" "$SERVER/download/bgp-agent-linux-$ARCH" -o "$TMP"
chmod 755 "$TMP"
"$TMP" version >/dev/null
mv -f "$TMP" "$BIN"

echo "==> Schreibe Konfiguration"
install -d -m 700 "$CONF_DIR"
cat > "$CONF_DIR/config.json" <<EOF
{
  "server": "$SERVER",
  "token": "$TOKEN",
  "pin_sha256": "$PIN",
  "interface": "wg-bgp",
  "dummy_interface": "bgp0",
  "table": 51820,
  "rule_priority": 10200,
  "interval_seconds": 30
}
EOF
chmod 600 "$CONF_DIR/config.json"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "==> Richte systemd Dienst ein"
  cat > /etc/systemd/system/bgp-agent.service <<'EOF'
[Unit]
Description=BGP Router Backend Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bgp-agent run -config /etc/bgp-agent/config.json
Restart=always
RestartSec=5
# Beim Stoppen bleiben Tunnel und Adressen bestehen (kein Ausfall bei Neustarts)
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable bgp-agent >/dev/null
  systemctl restart bgp-agent
  sleep 2
  systemctl --no-pager --lines=5 status bgp-agent || true
else
  echo "Kein systemd gefunden. Starte den Agent manuell: $BIN run -config $CONF_DIR/config.json"
fi

echo
echo "Fertig. Das Backend meldet sich in wenigen Sekunden im Webinterface."
`
