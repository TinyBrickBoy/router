package netcfg

import (
	"fmt"
	"strings"
)

// WGPeer ist ein WireGuard Peer.
type WGPeer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	Keepalive  int
}

// WGConfig ist eine WireGuard Konfiguration im Format von `wg setconf`.
type WGConfig struct {
	PrivateKey string
	ListenPort int
	Peers      []WGPeer
}

// Render erzeugt die Konfigurationsdatei.
func (c WGConfig) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String()
}

// SyncWireGuard schreibt die Konfiguration nach confPath und übernimmt sie mit
// `wg syncconf` ohne bestehende Sessions zu unterbrechen.
func (m *Manager) SyncWireGuard(iface, confPath string, cfg WGConfig) error {
	if err := m.R.WriteFile(confPath, []byte(cfg.Render()), 0o600); err != nil {
		return err
	}
	_, err := m.R.Run("wg", "syncconf", iface, confPath)
	return err
}
