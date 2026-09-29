package router

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tinybrickboy/router/internal/store"
)

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9_]+`)

func birdString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// GenerateBird erzeugt eine vollständige BIRD2 Konfiguration aus dem Zustand.
func GenerateBird(st store.State) (string, error) {
	s := st.Settings
	rid, err := netip.ParseAddr(s.RouterID)
	if err != nil || !rid.Is4() {
		return "", fmt.Errorf("router id %q muss eine IPv4 adresse sein (einstellungen)", s.RouterID)
	}
	if s.ASN == 0 {
		return "", fmt.Errorf("eigene ASN fehlt (einstellungen)")
	}
	var b strings.Builder
	b.WriteString("# Automatisch erzeugt von bgp-router. Änderungen werden überschrieben.\n\n")
	fmt.Fprintf(&b, "router id %s;\n", rid)
	b.WriteString("log syslog all;\n\n")
	b.WriteString("protocol device {\n\tscan time 10;\n}\n")

	rpki := s.RPKI.RTRHost != ""
	if rpki {
		port := s.RPKI.RTRPort
		if port == 0 {
			port = 323
		}
		b.WriteString("\nroa4 table rpki4;\nroa6 table rpki6;\n")
		fmt.Fprintf(&b, "\nprotocol rpki rpki_validator {\n\troa4 { table rpki4; };\n\troa6 { table rpki6; };\n\tremote %s port %d;\n\tretry keep 90;\n\trefresh keep 900;\n\texpire keep 172800;\n}\n", birdString(s.RPKI.RTRHost), port)
	}

	families := []struct {
		name string
		cfg  store.FamilySettings
		v6   bool
	}{{"ipv4", s.IPv4, false}, {"ipv6", s.IPv6, true}}

	for _, fam := range families {
		if !fam.cfg.Enabled {
			continue
		}
		static := "announce" + fam.name[3:]
		fmt.Fprintf(&b, "\nprotocol static %s {\n\t%s;\n", static, fam.name)
		for _, p := range st.Prefixes {
			pfx, err := netip.ParsePrefix(p.CIDR)
			if err != nil || !p.Announce || pfx.Addr().Is6() != fam.v6 {
				continue
			}
			fmt.Fprintf(&b, "\troute %s unreachable;\n", pfx.Masked())
		}
		b.WriteString("}\n")

		// Export Filter: nur eigene Ankündigungen, optional RPKI und Traffic Engineering
		roa := ""
		if rpki {
			// eigene Ankündigungen, die laut RPKI invalid wären, zurückhalten
			roa = fmt.Sprintf("roa_check(rpki%s, net, %d)", fam.name[3:], s.ASN)
		}
		te, err := teRules(st.Prefixes, fam.v6, s.ASN)
		if err != nil {
			return "", err
		}
		export := fmt.Sprintf("where proto = %q", static)
		if roa != "" {
			export += " && " + roa + " != ROA_INVALID"
		}
		if te != "" {
			filter := "export" + fam.name[3:]
			fmt.Fprintf(&b, "\nfilter %s {\n\tif proto != %q then reject;\n", filter, static)
			if roa != "" {
				fmt.Fprintf(&b, "\tif %s = ROA_INVALID then reject;\n", roa)
			}
			b.WriteString(te)
			b.WriteString("\taccept;\n}\n")
			export = "filter " + filter
		}

		for i, n := range fam.cfg.Neighbors {
			addr, err := netip.ParseAddr(n.Address)
			if err != nil {
				return "", fmt.Errorf("neighbor %q: ungültige adresse", n.Name)
			}
			name := nonIdent.ReplaceAllString(n.Name, "_")
			fmt.Fprintf(&b, "\nprotocol bgp %s {\n", strings.TrimRight(fmt.Sprintf("bgp%s_%d_%s", fam.name[3:], i+1, name), "_"))
			if n.Name != "" {
				fmt.Fprintf(&b, "\tdescription %s;\n", birdString(n.Name))
			}
			fmt.Fprintf(&b, "\tlocal as %d;\n", s.ASN)
			fmt.Fprintf(&b, "\tneighbor %s as %d;\n", addr, n.RemoteASN)
			if n.SourceAddress != "" {
				src, err := netip.ParseAddr(n.SourceAddress)
				if err != nil {
					return "", fmt.Errorf("neighbor %q: ungültige quelladresse", n.Name)
				}
				fmt.Fprintf(&b, "\tsource address %s;\n", src)
			}
			if n.Multihop > 0 {
				fmt.Fprintf(&b, "\tmultihop %d;\n", n.Multihop)
			}
			if n.Password != "" {
				fmt.Fprintf(&b, "\tpassword %s;\n", birdString(n.Password))
			}
			fmt.Fprintf(&b, "\t%s {\n\t\timport none;\n\t\texport %s;\n\t};\n}\n", fam.name, export)
		}
	}
	return b.String(), nil
}

// teRules erzeugt die Filterregeln für Prepend und Communities einer Adressfamilie.
func teRules(prefixes []store.Prefix, v6 bool, asn uint32) (string, error) {
	var b strings.Builder
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p.CIDR)
		if err != nil || !p.Announce || pfx.Addr().Is6() != v6 || (p.Prepend == 0 && p.Communities == "") {
			continue
		}
		cs, err := parseCommunities(p.Communities)
		if err != nil {
			return "", fmt.Errorf("präfix %s: %w", p.CIDR, err)
		}
		if p.Prepend < 0 || p.Prepend > maxPrepend {
			return "", fmt.Errorf("präfix %s: ungültiges prepend", p.CIDR)
		}
		fmt.Fprintf(&b, "\tif net = %s then {\n", pfx.Masked())
		for i := 0; i < p.Prepend; i++ {
			fmt.Fprintf(&b, "\t\tbgp_path.prepend(%d);\n", asn)
		}
		for _, c := range cs {
			if c.Large() {
				fmt.Fprintf(&b, "\t\tbgp_large_community.add((%d,%d,%d));\n", c.Parts[0], c.Parts[1], c.Parts[2])
			} else {
				fmt.Fprintf(&b, "\t\tbgp_community.add((%d,%d));\n", c.Parts[0], c.Parts[1])
			}
		}
		b.WriteString("\t}\n")
	}
	return b.String(), nil
}
