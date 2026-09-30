package netcfg

import (
	"net/netip"
	"os/exec"
	"strings"
)

// ForwardChain enthält die Freigaben für weitergeleiteten Verkehr durch den Tunnel.
const ForwardChain = "BGP-ROUTER-FWD"

// SyncForward erlaubt genau den weitergeleiteten Verkehr der zugewiesenen Netze
// durch iface: an sie (-o iface -d) und von ihnen (-i iface -s). Ohne diese
// Freigabe verwirft eine FORWARD Policy DROP (z.B. von Docker gesetzt) alle
// Pakete aus dem Internet an die Backends. tool ist iptables oder ip6tables und
// bekommt nur die Netze seiner Adressfamilie; ist es nicht installiert, gibt es
// auch keine Regeln, die etwas verwerfen.
func (m *Manager) SyncForward(tool, iface string, nets []netip.Prefix) error {
	if !m.R.DryRun {
		if _, err := exec.LookPath(tool); err != nil {
			return nil
		}
	}
	v6 := tool == "ip6tables"
	var rules [][]string
	for _, n := range nets {
		if n.Addr().Is6() != v6 {
			continue
		}
		n = n.Masked()
		rules = append(rules,
			[]string{"-A", ForwardChain, "-d", n.String(), "-o", iface, "-j", "ACCEPT"},
			[]string{"-A", ForwardChain, "-s", n.String(), "-i", iface, "-j", "ACCEPT"},
		)
	}

	want := []string{"-N " + ForwardChain}
	for _, r := range rules {
		want = append(want, strings.Join(r, " "))
	}
	out, err := m.R.Query(tool, "-w", "-S", ForwardChain)
	if err != nil {
		if _, err := m.R.Run(tool, "-w", "-N", ForwardChain); err != nil {
			return err
		}
		out = ""
	}
	if strings.Join(strings.Fields(out), " ") != strings.Join(want, " ") {
		// Inhalt veraltet (Zuweisungen oder Interface geändert): neu aufbauen
		if _, err := m.R.Run(tool, "-w", "-F", ForwardChain); err != nil {
			return err
		}
		for _, r := range rules {
			if _, err := m.R.Run(tool, append([]string{"-w"}, r...)...); err != nil {
				return err
			}
		}
	}
	if _, err := m.R.Query(tool, "-w", "-C", "FORWARD", "-j", ForwardChain); err != nil || m.R.DryRun {
		_, err := m.R.Run(tool, "-w", "-I", "FORWARD", "1", "-j", ForwardChain)
		return err
	}
	return nil
}
