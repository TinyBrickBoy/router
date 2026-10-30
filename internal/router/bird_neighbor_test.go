package router

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

// migrationState: alter Upstream plus BGP Session über den GRE Tunnel.
func migrationState() store.State {
	st := teState()
	st.Settings.IPv4.Neighbors = append(st.Settings.IPv4.Neighbors, store.Neighbor{Name: "ddos", Address: "100.64.0.4", RemoteASN: 209874, SourceAddress: "100.64.0.5"})
	return st
}

// goldenBird wurde mit v1.4.1 (ohne Optionen pro Neighbor) aus migrationState erzeugt.
const goldenBird = "# Automatisch erzeugt von bgp-router. Änderungen werden überschrieben.\n\nrouter id 198.51.100.1;\nlog syslog all;\n\nprotocol device {\n\tscan time 10;\n}\n\nroa4 table rpki4;\nroa6 table rpki6;\n\nprotocol rpki rpki_validator {\n\troa4 { table rpki4; };\n\troa6 { table rpki6; };\n\tremote \"127.0.0.1\" port 323;\n\tretry keep 90;\n\trefresh keep 900;\n\texpire keep 172800;\n}\n\nprotocol static announce4 {\n\tipv4;\n\troute 203.0.113.0/24 unreachable;\n\troute 198.51.100.0/24 unreachable;\n}\n\nfilter export4 {\n\tif proto != \"announce4\" then reject;\n\tif roa_check(rpki4, net, 4200000000) = ROA_INVALID then reject;\n\tif net = 203.0.113.0/24 then {\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_community.add((64515,100));\n\t\tbgp_large_community.add((64515,1,2));\n\t}\n\taccept;\n}\n\nprotocol bgp bgp4_1_up {\n\tdescription \"up\";\n\tlocal as 4200000000;\n\tneighbor 169.254.169.254 as 64515;\n\tmultihop 2;\n\tipv4 {\n\t\timport none;\n\t\texport filter export4;\n\t};\n}\n\nprotocol bgp bgp4_2_ddos {\n\tdescription \"ddos\";\n\tlocal as 4200000000;\n\tneighbor 100.64.0.4 as 209874;\n\tsource address 100.64.0.5;\n\tipv4 {\n\t\timport none;\n\t\texport filter export4;\n\t};\n}\n\nprotocol static announce6 {\n\tipv6;\n\troute 2001:db8:1000::/48 unreachable;\n}\n\nprotocol bgp bgp6_1_up6 {\n\tdescription \"up6\";\n\tlocal as 4200000000;\n\tneighbor 2001:19f0:ffff::1 as 64515;\n\tmultihop 2;\n\tipv6 {\n\t\timport none;\n\t\texport where proto = \"announce6\" && roa_check(rpki6, net, 4200000000) != ROA_INVALID;\n\t};\n}\n"

func TestBirdNeighborUnchanged(t *testing.T) {
	conf, err := GenerateBird(migrationState())
	if err != nil {
		t.Fatal(err)
	}
	if conf != goldenBird {
		t.Errorf("konfiguration ohne neighbor optionen hat sich geändert:\n%s", conf)
	}
	// Session über den Tunnel: direkt (kein multihop) mit eigener Tunneladresse als Quelle
	if !strings.Contains(conf, "\tneighbor 100.64.0.4 as 209874;\n\tsource address 100.64.0.5;\n\tipv4 {") {
		t.Errorf("gre session falsch:\n%s", conf)
	}
}

func TestBirdNeighborTrafficEngineering(t *testing.T) {
	// Schritt 1: neue Session, die nichts ankündigt
	st := migrationState()
	st.Settings.IPv4.Neighbors[1].ExportNone = true
	st.Settings.IPv4.Neighbors[1].Prepend = 3 // wird von "nur Session" überstimmt
	conf, err := GenerateBird(st)
	if err != nil {
		t.Fatal(err)
	}
	ddos := conf[strings.Index(conf, "protocol bgp bgp4_2_ddos"):]
	if !strings.Contains(ddos, "\t\texport none;\n") || strings.Contains(conf, "filter export_bgp4_2_ddos") {
		t.Errorf("nur session erwartet export none:\n%s", conf)
	}
	if strings.Replace(conf, "export none;", "export filter export4;", 1) != goldenBird {
		t.Errorf("andere neighbors verändert:\n%s", conf)
	}

	// Schritt 2: beide kündigen an, der alte Upstream mit Prepend
	st = migrationState()
	st.Settings.IPv4.Neighbors[0].Prepend = 2
	conf, err = GenerateBird(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"filter export_bgp4_1_up {\n\tif proto != \"announce4\" then reject;\n\tif roa_check(rpki4, net, 4200000000) = ROA_INVALID then reject;\n" +
			"\tif net = 203.0.113.0/24 then {\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_path.prepend(4200000000);\n\t\tbgp_community.add((64515,100));\n\t\tbgp_large_community.add((64515,1,2));\n\t}\n" +
			"\tbgp_path.prepend(4200000000);\n\tbgp_path.prepend(4200000000);\n\taccept;\n}\n\nprotocol bgp bgp4_1_up {",
		"\t\texport filter export_bgp4_1_up;\n",
		// die Session über den Tunnel behält den gemeinsamen Filter
		"neighbor 100.64.0.4 as 209874;\n\tsource address 100.64.0.5;\n\tipv4 {\n\t\timport none;\n\t\texport filter export4;\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("%q fehlt in\n%s", want, conf)
		}
	}

	// ohne RPKI und ohne Präfix TE: Filter nur mit Quelle und Prepend
	st.Settings.RPKI.RTRHost = ""
	for i := range st.Prefixes {
		st.Prefixes[i].Prepend, st.Prefixes[i].Communities = 0, ""
	}
	plain, err := GenerateBird(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "filter export_bgp4_1_up {\n\tif proto != \"announce4\" then reject;\n\tbgp_path.prepend(4200000000);\n\tbgp_path.prepend(4200000000);\n\taccept;\n}\n") ||
		!strings.Contains(plain, "export where proto = \"announce4\";") {
		t.Errorf("filter ohne rpki/te falsch:\n%s", plain)
	}

	st.Settings.IPv4.Neighbors[0].Prepend = maxPrepend + 1
	if _, err := GenerateBird(st); err == nil {
		t.Error("zu großes prepend akzeptiert")
	}

	bird, err := exec.LookPath("bird")
	if err != nil {
		t.Skip("bird nicht installiert")
	}
	none := migrationState()
	none.Settings.IPv4.Neighbors[1].ExportNone = true
	noneConf, _ := GenerateBird(none)
	for _, c := range []string{conf, plain, noneConf} {
		p := filepath.Join(t.TempDir(), "bird.conf")
		os.WriteFile(p, []byte(c), 0o600)
		if out, err := exec.Command(bird, "-p", "-c", p).CombinedOutput(); err != nil {
			t.Fatalf("bird lehnt die konfiguration ab: %v\n%s\n%s", err, out, c)
		}
	}
}
