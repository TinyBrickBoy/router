package agent

import (
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/api"
)

func TestValidateConfig(t *testing.T) {
	good := func() api.AgentConfig {
		return api.AgentConfig{
			ServerPublicKey: "cXq4idOjjflMdh5zXrtOG6Lmcn5iigohEVfz7OTlKlo=",
			Endpoint:        "198.51.100.1:51820", MTU: 1420, Keepalive: 25,
			TunnelAddrs: []string{"10.200.0.2/24"}, Routes: []string{"203.0.113.8/29", "2001:db8:1::/64"},
			Update: &api.Update{URL: "/download/bgp-agent-linux-amd64", SHA256: strings.Repeat("a", 64)},
		}
	}
	c := good()
	if err := validateConfig(&c); err != nil {
		t.Fatalf("gültige konfiguration abgelehnt: %v", err)
	}
	bad := map[string]func(*api.AgentConfig){
		"endpoint injection": func(c *api.AgentConfig) { c.Endpoint = "1.2.3.4:51820\n[Peer]" },
		"endpoint ohne port": func(c *api.AgentConfig) { c.Endpoint = "1.2.3.4" },
		"default route":      func(c *api.AgentConfig) { c.Routes = []string{"0.0.0.0/0"} },
		"v6 default route":   func(c *api.AgentConfig) { c.Routes = []string{"::/0"} },
		"fremde update url":  func(c *api.AgentConfig) { c.Update.URL = "https://evil.example/agent" },
		"pfad traversal":     func(c *api.AgentConfig) { c.Update.URL = "/download/bgp-agent-linux-../../x" },
		"kaputter key":       func(c *api.AgentConfig) { c.ServerPublicKey = "abc" },
		"mtu":                func(c *api.AgentConfig) { c.MTU = 100 },
	}
	for name, mod := range bad {
		c := good()
		mod(&c)
		if err := validateConfig(&c); err == nil {
			t.Errorf("%s: wurde akzeptiert", name)
		}
	}
}

func TestInsecureUpdateRefused(t *testing.T) {
	a := &Agent{Cfg: Config{Server: "http://router:8080"}}
	err := a.selfUpdate(&api.Update{URL: "/download/bgp-agent-linux-amd64", SHA256: strings.Repeat("b", 64)})
	if err == nil || !strings.Contains(err.Error(), "abgelehnt") {
		t.Fatalf("update über http nicht abgelehnt: %v", err)
	}
}
