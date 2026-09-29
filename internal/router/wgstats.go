package router

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/router/internal/store"
)

// wgPeer sind die Tunnel Daten eines Peers aus Sicht des Routers.
type wgPeer struct {
	Endpoint  string
	Handshake time.Time
	RX, TX    uint64 // vom Backend empfangen bzw. zum Backend gesendet
}

// TunnelUp: WireGuard erneuert den Handshake spätestens alle 2 Minuten.
func (p *wgPeer) TunnelUp() bool {
	return p != nil && !p.Handshake.IsZero() && time.Since(p.Handshake) < 3*time.Minute
}

// parseWGDump liest die Ausgabe von `wg show <iface> dump`.
func parseWGDump(out string) map[string]wgPeer {
	peers := map[string]wgPeer{}
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if i == 0 || len(f) < 8 { // erste Zeile beschreibt das Interface
			continue
		}
		p := wgPeer{Endpoint: f[2]}
		if p.Endpoint == "(none)" {
			p.Endpoint = ""
		}
		if ts, err := strconv.ParseInt(f[4], 10, 64); err == nil && ts > 0 {
			p.Handshake = time.Unix(ts, 0)
		}
		p.RX, _ = strconv.ParseUint(f[5], 10, 64)
		p.TX, _ = strconv.ParseUint(f[6], 10, 64)
		peers[f[0]] = p
	}
	return peers
}

// wgPeers liefert die Tunnel Daten pro Public Key (leer bei Fehler oder Dry-Run).
func (s *Server) wgPeers(st store.State) map[string]wgPeer {
	out, err := s.Runner.Query("wg", "show", st.Settings.WireGuard.Interface, "dump")
	if err != nil {
		return map[string]wgPeer{}
	}
	return parseWGDump(out)
}

// humanBytes formatiert Bytes mit binären Einheiten.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
