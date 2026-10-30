// Package api enthält die Datentypen zwischen Router (VPS) und Agent (Backend).
package api

// SyncRequest sendet der Agent regelmäßig an den Router.
type SyncRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Arch      string `json:"arch"`
}

// AgentConfig ist die gewünschte Konfiguration eines Backends.
type AgentConfig struct {
	ServerPublicKey string   `json:"server_public_key"`
	Endpoint        string   `json:"endpoint"`
	MTU             int      `json:"mtu"`
	Keepalive       int      `json:"keepalive"`
	TunnelAddrs     []string `json:"tunnel_addrs"`
	Routes          []string `json:"routes"`
	Update          *Update  `json:"update,omitempty"`
}

// Update fordert den Agent auf, sich auf ein neues Binary zu aktualisieren.
type Update struct {
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

// Network liefert der Router an die Edge Firewall (GET /api/v1/network).
type Network struct {
	Router      string              `json:"router"`
	ASN         uint32              `json:"asn"`
	Prefixes    []NetworkPrefix     `json:"prefixes"`
	Assignments []NetworkAssignment `json:"assignments"`
}

// NetworkPrefix ist ein eigenes Präfix des Routers.
type NetworkPrefix struct {
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
	Announce    bool   `json:"announce"`
}

// NetworkAssignment sagt, wohin eine IP oder ein Subnetz geroutet wird.
type NetworkAssignment struct {
	CIDR        string `json:"cidr"`
	Target      string `json:"target"`      // "local" oder Backend ID
	TargetName  string `json:"target_name"` // "Lokal (VPS)" oder Name des Backends
	Description string `json:"description"`
}
