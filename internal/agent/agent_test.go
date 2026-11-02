package agent

import (
	"net/netip"
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
		"default präfix":     func(c *api.AgentConfig) { c.Prefixes = []string{"0.0.0.0/0"} },
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

func TestPrefixRoutes(t *testing.T) {
	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/48", "192.0.2.0/24"}
	endpoints := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	own := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::5/128"),
		netip.MustParsePrefix("192.0.2.8/29"),
		netip.MustParsePrefix("203.0.113.7/32"),
	}
	got := prefixRoutes(prefixes, endpoints, own, "wg-bgp")
	if len(got) != 3 {
		t.Fatalf("erwartet 3 routen (endpoint präfix ausgelassen), bekommen %v", got)
	}
	if got[0].Dst.String() != "203.0.113.0/24" || got[0].Src.String() != "203.0.113.7" || got[0].Dev != "wg-bgp" || got[0].Table != "main" {
		t.Errorf("v4 route falsch: %+v", got[0])
	}
	if got[1].Dst.String() != "2001:db8::/48" || got[1].Src.String() != "2001:db8::5" {
		t.Errorf("v6 route falsch: %+v", got[1])
	}
	// nur ein Subnetz zugewiesen: erste Host Adresse daraus als Absender
	if got[2].Dst.String() != "192.0.2.0/24" || got[2].Src.String() != "192.0.2.9" {
		t.Errorf("subnetz route falsch: %+v", got[2])
	}
}

func TestPrefixRoutesResolvedEndpoint(t *testing.T) {
	// aufgelöster Hostname (v4 und v6) liegt in beiden Präfixen
	endpoints := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("2001:db8::1")}
	got := prefixRoutes([]string{"203.0.113.0/24", "2001:db8::/48"}, endpoints, nil, "wg-bgp")
	if len(got) != 0 {
		t.Fatalf("präfixe mit endpoint nicht ausgelassen: %v", got)
	}
}

func TestEndpointAddrs(t *testing.T) {
	got, err := endpointAddrs("198.51.100.1:51820")
	if err != nil || len(got) != 1 || got[0].String() != "198.51.100.1" {
		t.Fatalf("ip endpoint: %v %v", got, err)
	}
	got, err = endpointAddrs("[::ffff:198.51.100.1]:51820")
	if err != nil || len(got) != 1 || got[0].String() != "198.51.100.1" {
		t.Fatalf("v4 mapped endpoint: %v %v", got, err)
	}
	got, err = endpointAddrs("localhost:51820")
	if err != nil || len(got) == 0 {
		t.Fatalf("hostname endpoint nicht aufgelöst: %v %v", got, err)
	}
	if _, err := endpointAddrs("does-not-exist.invalid:51820"); err == nil {
		t.Fatal("unauflösbarer endpoint ohne fehler")
	}
}
