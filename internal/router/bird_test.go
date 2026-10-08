package router

import (
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestGenerateBird(t *testing.T) {
	st := store.Defaults()
	st.Settings.ASN = 4200000000
	st.Settings.RouterID = "198.51.100.1"
	st.Settings.IPv4.Neighbors = []store.Neighbor{{Name: "vultr v4", Address: "169.254.169.254", RemoteASN: 64515, Multihop: 2, Password: `pa"ss`}}
	st.Settings.IPv6.Neighbors = []store.Neighbor{{Name: "v6", Address: "2001:19f0:ffff::1", RemoteASN: 64515, SourceAddress: "2001:db8::1"}}
	st.Prefixes = []store.Prefix{
		{CIDR: "203.0.113.0/24", Announce: true},
		{CIDR: "2001:db8:1000::/48", Announce: true},
		{CIDR: "192.0.2.0/24", Announce: false},
	}
	conf, err := GenerateBird(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"router id 198.51.100.1;",
		"route 203.0.113.0/24 unreachable;",
		"route 2001:db8:1000::/48 unreachable;",
		"protocol bgp bgp4_1_vultr_v4 {",
		"local as 4200000000;",
		"neighbor 169.254.169.254 as 64515;",
		"multihop 2;",
		`password "pa\"ss";`,
		`export where proto = "announce4";`,
		"source address 2001:db8::1;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("fehlt: %q\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "192.0.2.0/24") {
		t.Error("pausiertes präfix wird angekündigt")
	}
	if shown := redactBird(conf); strings.Contains(shown, `pa\"ss`) || !strings.Contains(shown, "\tpassword \"***\";\n") {
		t.Errorf("bgp passwort in der anzeige nicht geschwärzt:\n%s", shown)
	}

	st.Settings.RPKI.RTRHost = "127.0.0.1"
	st.Settings.RPKI.RTRPort = 3323
	conf, _ = GenerateBird(st)
	for _, want := range []string{"roa4 table rpki4;", `remote "127.0.0.1" port 3323;`, `export where proto = "announce4" && roa_check(rpki4, net, 4200000000) != ROA_INVALID;`} {
		if !strings.Contains(conf, want) {
			t.Errorf("rpki: fehlt %q\n%s", want, conf)
		}
	}
	st.Settings.RPKI.RTRHost = ""

	st.Settings.IPv6.Enabled = false
	conf, _ = GenerateBird(st)
	if strings.Contains(conf, "ipv6") {
		t.Error("deaktivierte familie erscheint in der konfiguration")
	}

	st.Settings.RouterID = ""
	if _, err := GenerateBird(st); err == nil {
		t.Error("fehlende router id muss fehler liefern")
	}
}

func TestParseCIDR(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5":    "203.0.113.5/32",
		"203.0.113.5/24": "203.0.113.0/24",
		" 2001:db8::1 ":  "2001:db8::1/128",
		"2001:db8::1/48": "2001:db8::/48",
	}
	for in, want := range cases {
		p, err := parseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("parseCIDR(%q) = %v, %v; erwartet %s", in, p, err, want)
		}
	}
	if _, err := parseCIDR("kein netz"); err == nil {
		t.Error("ungültige eingabe akzeptiert")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shq(`http://a'$(id)'`); got != `'http://a'\''$(id)'\'''` {
		t.Errorf("shq: %s", got)
	}
}
