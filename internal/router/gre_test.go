package router

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/netcfg"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func ddosTunnel() store.GRETunnel {
	return store.GRETunnel{ID: "g1", Name: "gre-ddos", Local: "5.175.176.185", Remote: "5.83.150.1", Address: "100.64.0.5/31", MTU: 1476, ReplyRouting: true, Slot: 1}
}

func TestApplyGREDryRun(t *testing.T) {
	var buf bytes.Buffer
	r := &sysexec.Runner{DryRun: true, Logger: log.New(&buf, "", 0)}
	a := NewApplier(nil, r, t.TempDir())
	var errs []error
	add := func(step string, err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	routes := a.applyGRE(&netcfg.Manager{R: r}, []store.GRETunnel{ddosTunnel()}, add)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if len(routes) != 1 || routes[0].Table != "2101" || routes[0].Dev != "gre-ddos" || routes[0].Via.String() != "100.64.0.4" || routes[0].Dst.String() != "0.0.0.0/0" {
		t.Errorf("reply route: %+v", routes)
	}
	out := buf.String()
	for _, want := range []string{
		"ip link add dev gre-ddos type gre local 5.175.176.185 remote 5.83.150.1 ttl 64",
		"ip link set dev gre-ddos mtu 1476",
		"ip addr add 100.64.0.5/31 dev gre-ddos",
		"sysctl -q -w net.ipv4.conf.gre-ddos.rp_filter=2",
		"ip -4 rule add priority 10100 fwmark 0x100000/0xf00000 table 2101",
		"nft -f ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}

	// ohne Reply Routing keine Rule und keine Route
	buf.Reset()
	g := ddosTunnel()
	g.ReplyRouting = false
	if routes := a.applyGRE(&netcfg.Manager{R: r}, []store.GRETunnel{g}, add); len(routes) != 0 || strings.Contains(buf.String(), "rule add") {
		t.Errorf("reply routing trotz aus:\n%s", buf.String())
	}
}

// Live Zustand beim ersten Start der neuen Version: von Hand angelegtes
// gre-ddos, aber noch kein GRE Tunnel in den Einstellungen. Dann darf sich
// nichts ändern.
func TestApplyGREWithoutConfigKeepsHandmadeTunnel(t *testing.T) {
	var calls []string
	r := &sysexec.Runner{Logger: log.New(io.Discard, "", 0), Exec: func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch line {
		case "ip -d -j link show type gre":
			return `[{"ifname":"gre0","linkinfo":{"info_kind":"gre"}},{"ifname":"gre-ddos","linkinfo":{"info_kind":"gre","info_data":{"remote":"5.83.150.1","local":"5.175.176.185"}}}]`, nil
		case "ip -j -4 rule show":
			return `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`, nil
		case "nft list table ip bgp_router_gre":
			return "", errors.New("No such file or directory")
		}
		return "", nil
	}}
	a := NewApplier(nil, r, t.TempDir())
	routes := a.applyGRE(&netcfg.Manager{R: r}, nil, func(step string, err error) {
		if err != nil {
			t.Errorf("%s: %v", step, err)
		}
	})
	if len(routes) != 0 {
		t.Errorf("routen: %v", routes)
	}
	for _, c := range calls {
		if !strings.Contains(c, " show") && !strings.HasPrefix(c, "nft list") {
			t.Errorf("unerwartete änderung: %s", c)
		}
	}
}

func TestGRESettings(t *testing.T) {
	ts, st := newUserServer(t)
	a, csrf := loginAs(t, ts.URL, "admin", "passwort123")
	post := func(path string, v url.Values) string {
		v.Set("csrf", csrf)
		resp, err := a.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc.Query().Get("err")
	}
	form := func(kv ...string) url.Values {
		v := url.Values{"name": {"gre-ddos"}, "local": {"5.175.176.185"}, "remote": {"5.83.150.1"}, "address": {"100.64.0.5/31"}, "reply_routing": {"1"}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for _, bad := range []url.Values{
		form("name", "GRE_ddos"),
		form("name", "ein-viel-zu-langer-name"),
		form("name", "wg-bgp"),
		form("local", "2001:db8::1"),
		form("remote", "5.175.176.185"),
		form("address", "100.64.0.5"),
		form("mtu", "100"),
	} {
		if post("/settings/gre", bad) == "" {
			t.Errorf("ungültige eingabe akzeptiert: %v", bad)
		}
	}
	if e := post("/settings/gre", form()); e != "" {
		t.Fatal(e)
	}
	g := st.Get().Settings.GRE
	if len(g) != 1 || g[0].Name != "gre-ddos" || g[0].MTU != 1476 || !g[0].ReplyRouting || g[0].Slot != 1 || g[0].ID == "" {
		t.Fatalf("tunnel: %+v", g)
	}
	if post("/settings/gre", form()) == "" || post("/settings/gre", form("name", "gre-2")) == "" {
		t.Error("doppelter tunnel akzeptiert")
	}
	if e := post("/settings/gre", form("name", "gre-2", "remote", "5.83.150.2")); e != "" {
		t.Fatal(e)
	}
	id := g[0].ID
	if e := post("/settings/gre/"+id, form("mtu", "1400", "reply_routing", "")); e != "" {
		t.Fatal(e)
	}
	if g := st.Get().Settings.GRE; g[0].MTU != 1400 || g[0].ReplyRouting || g[0].Slot != 1 || g[1].Slot != 2 {
		t.Errorf("bearbeiten: %+v", g)
	}
	if e := post("/settings/wireguard", url.Values{"interface": {"gre-2"}, "listen_port": {"51820"}, "mtu": {"1420"}}); e == "" {
		t.Error("wireguard interface mit gre namen akzeptiert")
	}

	// Neighbor über den Tunnel mit "nur Session" und Prepend am alten Upstream
	if e := post("/settings/neighbors/ipv4", url.Values{"name": {"ddos"}, "address": {"100.64.0.4"}, "remote_asn": {"209874"}, "source": {"100.64.0.5"}, "export_none": {"1"}}); e != "" {
		t.Fatal(e)
	}
	if e := post("/settings/neighbors/ipv4", url.Values{"name": {"alt"}, "address": {"5.175.176.2"}, "remote_asn": {"198590"}, "prepend": {"3"}}); e != "" {
		t.Fatal(e)
	}
	if post("/settings/neighbors/ipv4", url.Values{"address": {"5.175.176.3"}, "remote_asn": {"198590"}, "prepend": {"11"}}) == "" {
		t.Error("prepend 11 akzeptiert")
	}
	n := st.Get().Settings.IPv4.Neighbors
	if len(n) != 2 || !n[0].ExportNone || n[0].Multihop != 0 || n[0].SourceAddress != "100.64.0.5" || n[1].Prepend != 3 || n[1].ExportNone {
		t.Errorf("neighbors: %+v", n)
	}
	if e := post("/settings/neighbors/ipv4/"+n[0].ID, url.Values{"name": {"ddos"}, "address": {"100.64.0.4"}, "remote_asn": {"209874"}, "source": {"100.64.0.5"}}); e != "" {
		t.Fatal(e)
	}
	if st.Get().Settings.IPv4.Neighbors[0].ExportNone {
		t.Error("nur session nicht abgeschaltet")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/settings", nil)
	body := readBody(t, a, req)
	for _, want := range []string{"GRE-Tunnel", "gre-ddos", "100.64.0.5/31", "/settings/gre/" + id, "Prepend 3×", `name="export_none"`} {
		if !strings.Contains(body, want) {
			t.Errorf("einstellungen: %q fehlt", want)
		}
	}

	// Viewer darf nichts ändern
	v, vcsrf := loginAs(t, ts.URL, "noc", "viewer123")
	for _, p := range []string{"/settings/gre", "/settings/gre/" + id, "/settings/gre/" + id + "/delete"} {
		vf := form("mtu", "1300")
		vf.Set("csrf", vcsrf)
		resp, _ := v.PostForm(ts.URL+p, vf)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer %s: %d", p, resp.StatusCode)
		}
	}
	if g := st.Get().Settings.GRE; len(g) != 2 || g[0].MTU != 1400 {
		t.Errorf("viewer hat geändert: %+v", g)
	}

	if e := post("/settings/gre/"+id+"/delete", url.Values{}); e != "" {
		t.Fatal(e)
	}
	if g := st.Get().Settings.GRE; len(g) != 1 || g[0].Name != "gre-2" {
		t.Errorf("löschen: %+v", g)
	}
	// freier Slot wird wiederverwendet
	if e := post("/settings/gre", form()); e != "" {
		t.Fatal(e)
	}
	if g := st.Get().Settings.GRE; g[1].Slot != 1 {
		t.Errorf("slot: %+v", g)
	}
}
