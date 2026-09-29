package router

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestParseCommunities(t *testing.T) {
	cs, err := parseCommunities("65000:100, 4200000000:1:2 65000:100")
	if err != nil || formatCommunities(cs) != "65000:100, 4200000000:1:2" {
		t.Fatalf("%v %q", err, formatCommunities(cs))
	}
	for _, bad := range []string{"70000:1", "1:2:3:4", "a:b", "65000"} {
		if _, err := parseCommunities(bad); err == nil {
			t.Errorf("%q akzeptiert", bad)
		}
	}
}

func teState() store.State {
	st := store.Defaults()
	st.Settings.ASN = 4200000000
	st.Settings.RouterID = "198.51.100.1"
	st.Settings.RPKI.RTRHost = "127.0.0.1"
	st.Settings.IPv4.Neighbors = []store.Neighbor{{Name: "up", Address: "169.254.169.254", RemoteASN: 64515, Multihop: 2}}
	st.Settings.IPv6.Neighbors = []store.Neighbor{{Name: "up6", Address: "2001:19f0:ffff::1", RemoteASN: 64515, Multihop: 2}}
	st.Prefixes = []store.Prefix{
		{CIDR: "203.0.113.0/24", Announce: true, Prepend: 2, Communities: "64515:100, 64515:1:2"},
		{CIDR: "198.51.100.0/24", Announce: true},
		{CIDR: "2001:db8:1000::/48", Announce: true},
	}
	return st
}

func TestBirdTrafficEngineering(t *testing.T) {
	conf, err := GenerateBird(teState())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"filter export4 {",
		"\tif proto != \"announce4\" then reject;",
		"\tif roa_check(rpki4, net, 4200000000) = ROA_INVALID then reject;",
		"\tif net = 203.0.113.0/24 then {\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_community.add((64515,100));\n\t\tbgp_large_community.add((64515,1,2));\n\t}",
		"export filter export4;",
		// IPv6 ohne Traffic Engineering bleibt beim einfachen Ausdruck
		"export where proto = \"announce6\" && roa_check(rpki6, net, 4200000000) != ROA_INVALID;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("%q fehlt in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "filter export6") {
		t.Error("unnötiger ipv6 filter")
	}

	// Mit installiertem BIRD die Syntax prüfen
	bird, err := exec.LookPath("bird")
	if err != nil {
		t.Skip("bird nicht installiert")
	}
	plain := teState()
	for i := range plain.Prefixes {
		plain.Prefixes[i].Prepend, plain.Prefixes[i].Communities = 0, ""
	}
	plainConf, err := GenerateBird(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{conf, plainConf} {
		p := filepath.Join(t.TempDir(), "bird.conf")
		os.WriteFile(p, []byte(c), 0o600)
		if out, err := exec.Command(bird, "-p", "-c", p).CombinedOutput(); err != nil {
			t.Fatalf("bird lehnt die konfiguration ab: %v\n%s\n%s", err, out, c)
		}
	}
}
