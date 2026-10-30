package netcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// GREAlias steht als Interface Alias an jedem GRE Tunnel, den der Router
// verwaltet (selbst angelegt oder aus der Konfiguration übernommen). Nur solche
// Tunnel werden wieder entfernt, fremde GRE Interfaces bleiben unberührt.
const GREAlias = "bgp-router"

// GRENftTable ist die nftables Tabelle (Familie ip) für MSS Clamping und Reply Routing.
const GRENftTable = "bgp_router_gre"

// Reply Routing: jeder Tunnel bekommt einen Slot (1..GREMaxSlots). Daraus ergeben
// sich Mark (Slot << 20 innerhalb von GREMarkMask), Routing Tabelle (GRETableBase
// + Slot) und eine fwmark Rule mit GRERulePriority. Die Bits überschneiden sich
// nicht mit 0x2000000 (Agents) und 0x4000000 (minecraft-xdp).
const (
	GREMarkMask     uint32 = 0x00f00000
	GREMaxSlots            = 15
	GRETableBase           = 2100
	GRERulePriority        = 10100
)

// GREMark liefert das Mark eines Slots.
func GREMark(slot int) uint32 { return uint32(slot) << 20 & GREMarkMask }

// GRETable liefert die Routing Tabelle eines Slots.
func GRETable(slot int) string { return strconv.Itoa(GRETableBase + slot) }

// GRETunnel beschreibt einen GRE Tunnel (IPv4).
type GRETunnel struct {
	Name    string
	Local   netip.Addr
	Remote  netip.Addr
	Address netip.Prefix // eigene Tunneladresse mit Präfixlänge
	MTU     int
	// Mark != 0 schaltet Reply Routing ein (siehe SyncGREFirewall).
	Mark uint32
}

// GREPeer liefert bei /31 und /30 die Adresse der Gegenstelle im Tunnelnetz.
func GREPeer(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	a := p.Addr().As4()
	switch p.Bits() {
	case 31:
		a[3] ^= 1
	case 30:
		switch a[3] & 3 {
		case 1:
			a[3]++
		case 2:
			a[3]--
		default:
			return netip.Addr{}, false // Netz- oder Broadcastadresse
		}
	default:
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(a), true
}

type greLinkInfo struct {
	Ifname   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	MTU      int      `json:"mtu"`
	Ifalias  string   `json:"ifalias"`
	Linkinfo struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Local  string `json:"local"`
			Remote string `json:"remote"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func (l greLinkInfo) endpoints() (local, remote netip.Addr) {
	local, _ = netip.ParseAddr(l.Linkinfo.InfoData.Local)
	remote, _ = netip.ParseAddr(l.Linkinfo.InfoData.Remote)
	return local, remote
}

func (m *Manager) linkDetails(args ...string) ([]greLinkInfo, error) {
	out, err := m.R.Query("ip", append([]string{"-d", "-j", "link", "show"}, args...)...)
	if err != nil {
		return nil, err
	}
	var links []greLinkInfo
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &links); err != nil {
			return nil, fmt.Errorf("ip link parsen: %w", err)
		}
	}
	return links, nil
}

// EnsureGRE legt den Tunnel an oder gleicht ihn an, ohne ihn unnötig neu zu
// erzeugen: ein vorhandenes GRE Interface mit gleichem local/remote (z.B. von
// Hand angelegt) wird übernommen, MTU, Adresse und Status werden nur bei
// Abweichung geändert. Neu angelegt wird der Link nur, wenn er fehlt oder
// sich local/remote geändert haben. Ein gleichnamiges Interface anderen Typs
// wird nie angefasst.
func (m *Manager) EnsureGRE(t GRETunnel) error {
	var cur *greLinkInfo
	if links, err := m.linkDetails("dev", t.Name); err == nil && len(links) == 1 {
		cur = &links[0]
	}
	if cur != nil && cur.Linkinfo.InfoKind != "gre" {
		return fmt.Errorf("interface %s existiert bereits und ist kein gre tunnel", t.Name)
	}
	if cur != nil {
		if l, r := cur.endpoints(); l != t.Local || r != t.Remote {
			if _, err := m.R.Run("ip", "link", "del", "dev", t.Name); err != nil {
				return err
			}
			cur = nil
		}
	}
	if cur == nil {
		if _, err := m.R.Run("ip", "link", "add", "dev", t.Name, "type", "gre", "local", t.Local.String(), "remote", t.Remote.String(), "ttl", "64"); err != nil {
			return err
		}
		cur = &greLinkInfo{}
	}
	if cur.Ifalias != GREAlias {
		if _, err := m.R.Run("ip", "link", "set", "dev", t.Name, "alias", GREAlias); err != nil {
			return err
		}
	}
	if t.MTU > 0 && cur.MTU != t.MTU {
		if _, err := m.R.Run("ip", "link", "set", "dev", t.Name, "mtu", strconv.Itoa(t.MTU)); err != nil {
			return err
		}
	}
	if err := m.SyncAddresses(t.Name, []netip.Prefix{t.Address}); err != nil {
		return err
	}
	if !slices.Contains(cur.Flags, "UP") {
		if _, err := m.R.Run("ip", "link", "set", "dev", t.Name, "up"); err != nil {
			return err
		}
	}
	// Pakete aus dem Internet kommen mit Quelladressen an, deren Route über das
	// normale Interface zeigt: striktes rp_filter würde sie verwerfen.
	return m.Sysctl("net.ipv4.conf."+t.Name+".rp_filter", "2")
}

// RemoveStaleGRE entfernt verwaltete GRE Tunnel (Alias GREAlias), die nicht in keep stehen.
func (m *Manager) RemoveStaleGRE(keep []string) error {
	links, err := m.linkDetails("type", "gre")
	if err != nil {
		return err
	}
	var errs []error
	for _, l := range links {
		if l.Ifalias != GREAlias || l.Linkinfo.InfoKind != "gre" || slices.Contains(keep, l.Ifname) {
			continue
		}
		if _, err := m.R.Run("ip", "link", "del", "dev", l.Ifname); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// MarkRule ist eine "fwmark Mark/Mask lookup Table" Policy Rule (IPv4).
type MarkRule struct {
	Mark, Mask uint32
	Table      string
}

func (r MarkRule) key() string { return fmt.Sprintf("0x%x/0x%x|%s", r.Mark, r.Mask, r.Table) }

// SyncMarkRules setzt die IPv4 fwmark Rules mit priority exakt auf desired.
// Rules anderer Prioritäten bleiben unberührt.
func (m *Manager) SyncMarkRules(priority int, desired []MarkRule) error {
	prio := strconv.Itoa(priority)
	want := map[string]MarkRule{}
	for _, r := range desired {
		want[r.key()] = r
	}
	out, err := m.R.Query("ip", "-j", "-4", "rule", "show")
	if err != nil {
		if len(want) == 0 {
			return nil
		}
		return err
	}
	var entries []struct {
		Priority int    `json:"priority"`
		Fwmark   string `json:"fwmark"`
		Fwmask   string `json:"fwmask"`
		Table    any    `json:"table"`
	}
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &entries); err != nil {
			return fmt.Errorf("ip rule parsen: %w", err)
		}
	}
	var errs []error
	for _, e := range entries {
		if e.Priority != priority || e.Fwmark == "" {
			continue
		}
		mark, err1 := strconv.ParseUint(e.Fwmark, 0, 32)
		mask, err2 := uint64(0xffffffff), error(nil)
		if e.Fwmask != "" {
			mask, err2 = strconv.ParseUint(e.Fwmask, 0, 32)
		}
		if err1 != nil || err2 != nil {
			continue
		}
		cur := MarkRule{Mark: uint32(mark), Mask: uint32(mask), Table: fmt.Sprint(e.Table)}
		if _, ok := want[cur.key()]; ok {
			delete(want, cur.key())
			continue
		}
		mk := fmt.Sprintf("0x%x/0x%x", cur.Mark, cur.Mask)
		if _, err := m.R.Run("ip", "-4", "rule", "del", "priority", prio, "fwmark", mk, "table", cur.Table); err != nil {
			errs = append(errs, err)
		}
	}
	for _, k := range sortedKeys(want) {
		r := want[k]
		mk := fmt.Sprintf("0x%x/0x%x", r.Mark, r.Mask)
		if _, err := m.R.Run("ip", "-4", "rule", "add", "priority", prio, "fwmark", mk, "table", r.Table); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// greNftScript erzeugt die nftables Tabelle für alle Tunnel. Die erste Zeile
// legt die Tabelle an, falls sie fehlt, damit "delete" nicht scheitert; das
// ganze Skript wird von nft atomar übernommen, es gibt also keinen Moment ohne
// Regeln. Der Hash im Kommentar zeigt, ob die Tabelle schon aktuell ist.
func greNftScript(tunnels []GRETunnel) (script, hash string) {
	var body strings.Builder
	body.WriteString("\tchain forward {\n\t\ttype filter hook forward priority mangle; policy accept;\n")
	for _, t := range tunnels {
		// MSS an die MTU der jeweiligen Route anpassen, in beide Richtungen
		fmt.Fprintf(&body, "\t\toifname %q tcp flags syn tcp option maxseg size set rt mtu\n", t.Name)
		fmt.Fprintf(&body, "\t\tiifname %q tcp flags syn tcp option maxseg size set rt mtu\n", t.Name)
	}
	body.WriteString("\t}\n")

	var pre, out strings.Builder
	keep := fmt.Sprintf("0x%08x", ^GREMarkMask)
	mask := fmt.Sprintf("0x%08x", GREMarkMask)
	for _, t := range tunnels {
		if t.Mark == 0 {
			continue
		}
		mk := fmt.Sprintf("0x%08x", t.Mark)
		// neue Verbindungen aus dem Tunnel merken
		fmt.Fprintf(&pre, "\t\tiifname %q ct state new ct mark set ct mark and %s or %s\n", t.Name, keep, mk)
		// Antworten (z.B. von den Backends über WireGuard) bekommen das Mark für die fwmark Rule
		fmt.Fprintf(&pre, "\t\tiifname != %q ct mark and %s == %s meta mark set meta mark and %s or %s\n", t.Name, mask, mk, keep, mk)
		// Eigene Antworten des Routers: das Mark in der output route Kette löst eine neue Routing Entscheidung aus
		fmt.Fprintf(&out, "\t\tct mark and %s == %s meta mark set meta mark and %s or %s\n", mask, mk, keep, mk)
		// Das gekapselte GRE Paket behält das Mark des inneren Pakets: nie in den eigenen Tunnel routen
		fmt.Fprintf(&out, "\t\tip daddr %s ip protocol gre meta mark and %s != 0 meta mark set meta mark and %s\n", t.Remote, mask, keep)
	}
	if pre.Len() > 0 {
		body.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
		body.WriteString(pre.String())
		body.WriteString("\t}\n")
		body.WriteString("\tchain output {\n\t\ttype route hook output priority mangle; policy accept;\n")
		body.WriteString(out.String())
		body.WriteString("\t}\n")
	}
	sum := sha256.Sum256([]byte(body.String()))
	hash = hex.EncodeToString(sum[:8])
	script = fmt.Sprintf("table ip %[1]s\ndelete table ip %[1]s\ntable ip %[1]s {\n\tcomment \"%[2]s %[3]s\"\n%[4]s}\n", GRENftTable, GREAlias, hash, body.String())
	return script, hash
}

// SyncGREFirewall richtet die nftables Tabelle GRENftTable ein:
//   - MSS Clamping für TCP SYN in und aus jedem Tunnel
//   - Reply Routing für Tunnel mit Mark: neue Verbindungen, die über den Tunnel
//     ankommen, bekommen das Mark als Connmark, Pakete dieser Verbindungen aus
//     anderen Interfaces und vom Router selbst das Mark als fwmark. Eine fwmark
//     Rule (SyncMarkRules) schickt sie in die Tabelle des Tunnels. Nur die Bits
//     in GREMarkMask werden gesetzt und verglichen, andere Marks bleiben
//     erhalten; Verbindungen über andere Interfaces bleiben unmarkiert.
//
// Das Skript wird nach path geschrieben und nur übernommen, wenn sich etwas
// geändert hat. Ohne Tunnel wird die Tabelle entfernt.
func (m *Manager) SyncGREFirewall(path string, tunnels []GRETunnel) error {
	cur, err := m.R.Query("nft", "list", "table", "ip", GRENftTable)
	exists := err == nil && !m.R.DryRun
	if len(tunnels) == 0 {
		if !exists {
			return nil
		}
		_, err := m.R.Run("nft", "delete", "table", "ip", GRENftTable)
		return err
	}
	script, hash := greNftScript(tunnels)
	if exists && strings.Contains(cur, hash) {
		return nil
	}
	if err := m.R.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	_, err = m.R.Run("nft", "-f", path)
	return err
}
