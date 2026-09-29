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
