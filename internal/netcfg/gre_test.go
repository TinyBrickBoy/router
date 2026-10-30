package netcfg

import (
	"errors"
	"io"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/sysexec"
)

// fakeSys simuliert Systembefehle: out liefert die Ausgabe je Befehlszeile,
// fehlende Einträge in out mit fail=true schlagen fehl.
type fakeSys struct {
	out   map[string]string
	fail  map[string]bool
	calls []string
}

func (f *fakeSys) manager() *Manager {
	return &Manager{R: &sysexec.Runner{Logger: log.New(io.Discard, "", 0), Exec: func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, line)
		if f.fail[line] {
			return "", errors.New("fehlgeschlagen")
		}
		return f.out[line], nil
	}}}
}

// changes liefert alle verändernden Befehle (ohne show/list).
func (f *fakeSys) changes() []string {
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, " show") || strings.HasPrefix(c, "nft list") {
			continue
		}
		out = append(out, c)
	}
	return out
}

var ddos = GRETunnel{
	Name:    "gre-ddos",
	Local:   netip.MustParseAddr("5.175.176.185"),
	Remote:  netip.MustParseAddr("5.83.150.1"),
	Address: netip.MustParsePrefix("100.64.0.5/31"),
	MTU:     1476,
	Mark:    GREMark(1),
}

// handGRE ist die Ausgabe von "ip -d -j link show dev gre-ddos" für den von Hand angelegten Tunnel.
const handGRE = `[{"ifindex":7,"ifname":"gre-ddos","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1476,"operstate":"UNKNOWN","link_type":"gre","linkinfo":{"info_kind":"gre","info_data":{"remote":"5.83.150.1","local":"5.175.176.185","ttl":64,"pmtudisc":true}}}]`

const handAddr = `[{"ifname":"gre-ddos","addr_info":[{"family":"inet","local":"100.64.0.5","prefixlen":31,"scope":"global"}]}]`

func TestGREPeer(t *testing.T) {
	for in, want := range map[string]string{
		"100.64.0.5/31": "100.64.0.4",
		"100.64.0.4/31": "100.64.0.5",
		"10.0.0.1/30":   "10.0.0.2",
		"10.0.0.2/30":   "10.0.0.1",
	} {
		if p, ok := GREPeer(netip.MustParsePrefix(in)); !ok || p.String() != want {
			t.Errorf("GREPeer(%s) = %v %v, erwartet %s", in, p, ok, want)
		}
	}
	for _, in := range []string{"10.0.0.0/30", "10.0.0.1/24", "10.0.0.1/32"} {
		if p, ok := GREPeer(netip.MustParsePrefix(in)); ok {
			t.Errorf("GREPeer(%s) = %v, erwartet keine gegenstelle", in, p)
		}
	}
	if GREMark(1) != 0x100000 || GREMark(15) != 0xf00000 || GREMark(1)&(0x2000000|0x4000000) != 0 || GRETable(1) != "2101" {
		t.Error("mark/tabelle falsch")
	}
}

func TestEnsureGREAdoptsExisting(t *testing.T) {
	f := &fakeSys{out: map[string]string{
		"ip -d -j link show dev gre-ddos": handGRE,
		"ip -j addr show dev gre-ddos":    handAddr,
	}}
	if err := f.manager().EnsureGRE(ddos); err != nil {
		t.Fatal(err)
	}
	// nur Alias setzen und rp_filter, kein Löschen/Neuanlegen, keine Adress-, MTU- oder Statusänderung
	want := []string{
		"ip link set dev gre-ddos alias bgp-router",
		"sysctl -q -w net.ipv4.conf.gre-ddos.rp_filter=2",
	}
	if got := f.changes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("übernehmen ändert zu viel:\n%s", strings.Join(got, "\n"))
	}

	// bereits übernommen: nur noch rp_filter
	f.out["ip -d -j link show dev gre-ddos"] = strings.Replace(handGRE, `"mtu":1476,`, `"mtu":1476,"ifalias":"bgp-router",`, 1)
	f.calls = nil
	if err := f.manager().EnsureGRE(ddos); err != nil {
		t.Fatal(err)
	}
	if got := f.changes(); len(got) != 1 || !strings.HasPrefix(got[0], "sysctl") {
		t.Errorf("unerwartete änderungen: %v", got)
	}
}

func TestEnsureGREFixes(t *testing.T) {
	// MTU, Adresse und Status abweichend: angleichen ohne neu anzulegen
	link := strings.NewReplacer(`"mtu":1476`, `"mtu":1400`, `"UP",`, ``).Replace(handGRE)
	f := &fakeSys{out: map[string]string{
		"ip -d -j link show dev gre-ddos": link,
		"ip -j addr show dev gre-ddos":    strings.Replace(handAddr, "100.64.0.5", "100.64.0.9", 1),
	}}
	if err := f.manager().EnsureGRE(ddos); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.changes(), "\n")
	for _, want := range []string{
		"ip link set dev gre-ddos mtu 1476",
		"ip addr del 100.64.0.9/31 dev gre-ddos",
		"ip addr add 100.64.0.5/31 dev gre-ddos",
		"ip link set dev gre-ddos up",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "link del") || strings.Contains(got, "link add") {
		t.Errorf("link neu angelegt:\n%s", got)
	}

	// Remote geändert: neu anlegen
	f = &fakeSys{out: map[string]string{"ip -d -j link show dev gre-ddos": strings.Replace(handGRE, "5.83.150.1", "5.83.150.2", 1)}}
	if err := f.manager().EnsureGRE(ddos); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(f.changes(), "\n")
	if !strings.Contains(got, "ip link del dev gre-ddos\nip link add dev gre-ddos type gre local 5.175.176.185 remote 5.83.150.1 ttl 64") {
		t.Errorf("erwartet neu anlegen:\n%s", got)
	}

	// fehlt: anlegen
	f = &fakeSys{fail: map[string]bool{"ip -d -j link show dev gre-ddos": true}}
	if err := f.manager().EnsureGRE(ddos); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(f.changes(), "\n")
	for _, want := range []string{"ip link add dev gre-ddos type gre", "alias bgp-router", "mtu 1476", "ip addr add 100.64.0.5/31", "ip link set dev gre-ddos up", "rp_filter=2"} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}

	// anderer Typ mit gleichem Namen: nie anfassen
	f = &fakeSys{out: map[string]string{"ip -d -j link show dev gre-ddos": `[{"ifname":"gre-ddos","linkinfo":{"info_kind":"wireguard"}}]`}}
	if err := f.manager().EnsureGRE(ddos); err == nil || len(f.changes()) != 0 {
		t.Errorf("fremdes interface verändert: %v %v", err, f.changes())
	}
}

func TestRemoveStaleGRE(t *testing.T) {
	f := &fakeSys{out: map[string]string{"ip -d -j link show type gre": `[
		{"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"remote":"any","local":"any"}}},
		{"ifname":"gre-hand","linkinfo":{"info_kind":"gre","info_data":{"remote":"192.0.2.1","local":"198.51.100.1"}}},
		{"ifname":"gre-old","ifalias":"bgp-router","linkinfo":{"info_kind":"gre","info_data":{"remote":"192.0.2.2","local":"198.51.100.1"}}},
		{"ifname":"gre-ddos","ifalias":"bgp-router","linkinfo":{"info_kind":"gre","info_data":{"remote":"5.83.150.1","local":"5.175.176.185"}}}]`}}
	if err := f.manager().RemoveStaleGRE([]string{"gre-ddos"}); err != nil {
		t.Fatal(err)
	}
	if got := f.changes(); len(got) != 1 || got[0] != "ip link del dev gre-old" {
		t.Errorf("nur gre-old darf entfernt werden: %v", got)
	}
}

func TestSyncMarkRules(t *testing.T) {
	f := &fakeSys{out: map[string]string{"ip -j -4 rule show": `[
		{"priority":0,"src":"all","table":"local"},
		{"priority":100,"src":"all","fwmark":"0x4000000","table":"100"},
		{"priority":10100,"src":"all","fwmark":"0x100000","fwmask":"0xf00000","table":"2101"},
		{"priority":10100,"src":"all","fwmark":"0x200000","fwmask":"0xf00000","table":"2102"},
		{"priority":32766,"src":"all","table":"main"}]`}}
	err := f.manager().SyncMarkRules(GRERulePriority, []MarkRule{
		{Mark: GREMark(1), Mask: GREMarkMask, Table: GRETable(1)},
		{Mark: GREMark(3), Mask: GREMarkMask, Table: GRETable(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "ip -4 rule del priority 10100 fwmark 0x200000/0xf00000 table 2102\nip -4 rule add priority 10100 fwmark 0x300000/0xf00000 table 2103"
	if got := strings.Join(f.changes(), "\n"); got != want {
		t.Errorf("rules:\n%s\nerwartet:\n%s", got, want)
	}
}

func TestGRENftScript(t *testing.T) {
	plain := ddos
	plain.Mark = 0
	script, hash := greNftScript([]GRETunnel{plain})
	for _, want := range []string{
		"table ip bgp_router_gre\ndelete table ip bgp_router_gre\ntable ip bgp_router_gre {\n\tcomment \"bgp-router " + hash + "\"\n",
		"type filter hook forward priority mangle; policy accept;",
		"\t\toifname \"gre-ddos\" tcp flags syn tcp option maxseg size set rt mtu\n",
		"\t\tiifname \"gre-ddos\" tcp flags syn tcp option maxseg size set rt mtu\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("fehlt %q in\n%s", want, script)
		}
	}
	if strings.Contains(script, "mark") {
		t.Errorf("ohne reply routing keine marks:\n%s", script)
	}

	script, hash2 := greNftScript([]GRETunnel{ddos})
	if hash2 == hash {
		t.Error("hash ändert sich nicht")
	}
	for _, want := range []string{
		"type filter hook prerouting priority mangle; policy accept;",
		"\t\tiifname \"gre-ddos\" ct state new ct mark set ct mark and 0xff0fffff or 0x00100000\n",
		"\t\tiifname != \"gre-ddos\" ct mark and 0x00f00000 == 0x00100000 meta mark set meta mark and 0xff0fffff or 0x00100000\n",
		"type route hook output priority mangle; policy accept;",
		"\t\tct mark and 0x00f00000 == 0x00100000 meta mark set meta mark and 0xff0fffff or 0x00100000\n",
		"\t\tip daddr 5.83.150.1 ip protocol gre meta mark and 0x00f00000 != 0 meta mark set meta mark and 0xff0fffff\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("fehlt %q in\n%s", want, script)
		}
	}
}

func TestSyncGREFirewall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gre.nft")
	_, hash := greNftScript([]GRETunnel{ddos})

	// aktuell: nichts tun
	f := &fakeSys{out: map[string]string{"nft list table ip bgp_router_gre": "table ip bgp_router_gre {\n\tcomment \"bgp-router " + hash + "\"\n}"}}
	if err := f.manager().SyncGREFirewall(path, []GRETunnel{ddos}); err != nil || len(f.changes()) != 0 {
		t.Errorf("unnötig neu geladen: %v %v", err, f.changes())
	}
	// fehlt: laden
	f = &fakeSys{fail: map[string]bool{"nft list table ip bgp_router_gre": true}}
	if err := f.manager().SyncGREFirewall(path, []GRETunnel{ddos}); err != nil || strings.Join(f.changes(), "") != "nft -f "+path {
		t.Errorf("nicht geladen: %v %v", err, f.changes())
	}
	// keine Tunnel und keine Tabelle (z.B. bisheriger Zustand ohne GRE): nichts tun
	if err := f.manager().SyncGREFirewall(path, nil); err != nil || len(f.changes()) != 1 {
		t.Errorf("ohne tunnel verändert: %v %v", err, f.changes())
	}
	// keine Tunnel mehr: Tabelle entfernen
	f = &fakeSys{out: map[string]string{"nft list table ip bgp_router_gre": "table ip bgp_router_gre {}"}}
	if err := f.manager().SyncGREFirewall(path, nil); err != nil || strings.Join(f.changes(), "") != "nft delete table ip bgp_router_gre" {
		t.Errorf("tabelle nicht entfernt: %v %v", err, f.changes())
	}
}
