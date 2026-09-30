package netcfg

import (
	"bytes"
	"log"
	"net/netip"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/sysexec"
)

func TestLocalPlan(t *testing.T) {
	addrs, routes := LocalPlan([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.5/32"),
		netip.MustParsePrefix("203.0.113.64/28"),
		netip.MustParsePrefix("2001:db8::1/128"),
	})
	if len(addrs) != 2 || addrs[0].String() != "203.0.113.5/32" {
		t.Errorf("addrs %v", addrs)
	}
	if len(routes) != 1 || routes[0].Type != "local" || routes[0].Table != "local" || routes[0].Dst.String() != "203.0.113.64/28" {
		t.Errorf("routes %v", routes)
	}
}

func TestWGRender(t *testing.T) {
	c := WGConfig{PrivateKey: "priv", ListenPort: 51820, Peers: []WGPeer{{PublicKey: "pub", AllowedIPs: []string{"10.0.0.2/32", "203.0.113.0/29"}, Endpoint: "1.2.3.4:51820", Keepalive: 25}}}
	out := c.Render()
	for _, want := range []string{"ListenPort = 51820", "AllowedIPs = 10.0.0.2/32, 203.0.113.0/29", "Endpoint = 1.2.3.4:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
}

func TestSyncForwardDryRun(t *testing.T) {
	var buf bytes.Buffer
	m := &Manager{R: &sysexec.Runner{DryRun: true, Logger: log.New(&buf, "", 0)}}
	nets := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.67/32"),
		netip.MustParsePrefix("2001:db8::/64"),
	}
	if err := m.SyncForward("iptables", "wg-bgp", nets); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"iptables -w -A BGP-ROUTER-FWD -d 203.0.113.67/32 -o wg-bgp -j ACCEPT",
		"iptables -w -A BGP-ROUTER-FWD -s 203.0.113.67/32 -i wg-bgp -j ACCEPT",
		"iptables -w -I FORWARD 1 -j BGP-ROUTER-FWD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
	// kein pauschales Accept für den Tunnel und keine fremde Adressfamilie
	for _, bad := range []string{"BGP-ROUTER-FWD -i wg-bgp", "BGP-ROUTER-FWD -o wg-bgp", "2001:db8"} {
		if strings.Contains(out, bad) {
			t.Errorf("unerwartet %q in\n%s", bad, out)
		}
	}
}

func TestSyncDryRun(t *testing.T) {
	var buf bytes.Buffer
	m := &Manager{R: &sysexec.Runner{DryRun: true, Logger: log.New(&buf, "", 0)}}
	err := m.SyncRoutes([]Route{
		{Type: "unreachable", Dst: netip.MustParsePrefix("203.0.113.0/24")},
		{Dst: netip.MustParsePrefix("203.0.113.8/29"), Dev: "wg-bgp"},
		{Type: "local", Dst: netip.MustParsePrefix("203.0.113.64/28"), Dev: "lo", Table: "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"ip route replace unreachable 203.0.113.0/24 table main proto 201",
		"ip route replace 203.0.113.8/29 dev wg-bgp table main proto 201",
		"ip route replace local 203.0.113.64/28 dev lo table local proto 201",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
}
