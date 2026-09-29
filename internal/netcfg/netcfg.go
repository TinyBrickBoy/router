// Package netcfg setzt Adressen, Routen, Policy Rules und WireGuard über iproute2 / wg.
// Alle von uns angelegten Routen tragen das Protokoll RouteProto, damit veraltete
// Einträge sicher erkannt und entfernt werden können.
package netcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/tinybrickboy/router/internal/sysexec"
)

// RouteProto markiert alle von dieser Software verwalteten Routen.
const RouteProto = "201"

// Manager kapselt die Netzwerkkonfiguration.
type Manager struct {
	R *sysexec.Runner
}

// LinkExists prüft ob ein Interface existiert.
func (m *Manager) LinkExists(name string) bool {
	if m.R.DryRun {
		return true
	}
	_, err := m.R.Query("ip", "link", "show", "dev", name)
	return err == nil
}

// EnsureLink legt ein Interface vom Typ kind an (dummy, wireguard) und aktiviert es.
func (m *Manager) EnsureLink(name, kind string, mtu int) error {
	if !m.LinkExists(name) {
		if _, err := m.R.Run("ip", "link", "add", "dev", name, "type", kind); err != nil {
			return err
		}
	}
	if mtu > 0 {
		if _, err := m.R.Run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
			return err
		}
	}
	_, err := m.R.Run("ip", "link", "set", "dev", name, "up")
	return err
}

// DeleteLink entfernt ein Interface falls vorhanden.
func (m *Manager) DeleteLink(name string) error {
	if !m.LinkExists(name) {
		return nil
	}
	_, err := m.R.Run("ip", "link", "del", "dev", name)
	return err
}

// Sysctl setzt einen Kernel Parameter.
func (m *Manager) Sysctl(key, value string) error {
	_, err := m.R.Run("sysctl", "-q", "-w", key+"="+value)
	return err
}

// SyncAddresses sorgt dafür, dass auf dev genau die gewünschten Adressen liegen
// (Link Local Adressen werden ignoriert).
func (m *Manager) SyncAddresses(dev string, desired []netip.Prefix) error {
	out, err := m.R.Query("ip", "-j", "addr", "show", "dev", dev)
	if err != nil {
		return err
	}
	var links []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &links); err != nil {
			return fmt.Errorf("ip addr parsen: %w", err)
		}
	}
	current := map[string]bool{}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			if a.Scope == "link" {
				continue
			}
			addr, err := netip.ParseAddr(a.Local)
			if err != nil {
				continue
			}
			current[netip.PrefixFrom(addr, a.Prefixlen).String()] = true
		}
	}
	want := map[string]netip.Prefix{}
	for _, p := range desired {
		want[p.String()] = p
	}
	var errs []error
	for k := range current {
		if _, ok := want[k]; !ok {
			if _, err := m.R.Run("ip", "addr", "del", k, "dev", dev); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, k := range sortedKeys(want) {
		if current[k] {
			continue
		}
		args := []string{"addr", "add", k, "dev", dev}
		if want[k].Addr().Is6() {
			args = append(args, "nodad")
		}
		if _, err := m.R.Run("ip", args...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Route beschreibt eine verwaltete Kernel Route.
type Route struct {
	Type  string // unicast, unreachable, local
	Dst   netip.Prefix
	Dev   string
	Table string // main, local oder Nummer
}

func (r Route) norm() Route {
	if r.Type == "" {
		r.Type = "unicast"
	}
	if r.Table == "" {
		r.Table = "main"
	}
	r.Dst = r.Dst.Masked()
	return r
}

func (r Route) key() string {
	r = r.norm()
	return r.Type + "|" + r.Dst.String() + "|" + r.Table
}

// SyncRoutes setzt alle gewünschten Routen und entfernt verwaltete Routen, die nicht mehr gewünscht sind.
func (m *Manager) SyncRoutes(desired []Route) error {
	want := map[string]Route{}
	for _, r := range desired {
		r = r.norm()
		want[r.key()] = r
	}
	var errs []error
	for _, fam := range []string{"-4", "-6"} {
		out, err := m.R.Query("ip", "-j", fam, "route", "show", "table", "all", "proto", RouteProto)
		if err != nil {
			if wantsFamily(fam, func(yield func(netip.Prefix) bool) {
				for _, r := range want {
					if !yield(r.Dst) {
						return
					}
				}
			}) {
				errs = append(errs, err)
			}
			continue // z.B. IPv6 im Kernel deaktiviert und nichts für IPv6 konfiguriert
		}
		var entries []struct {
			Type  string `json:"type"`
			Dst   string `json:"dst"`
			Table any    `json:"table"`
		}
		if strings.TrimSpace(out) != "" {
			if err := json.Unmarshal([]byte(out), &entries); err != nil {
				errs = append(errs, fmt.Errorf("ip route parsen: %w", err))
				continue
			}
		}
		for _, e := range entries {
			dst, ok := parseDst(e.Dst, fam == "-6")
			if !ok {
				continue
			}
			table := "main"
			if e.Table != nil {
				table = fmt.Sprint(e.Table)
			}
			cur := Route{Type: e.Type, Dst: dst, Table: table}.norm()
			if _, ok := want[cur.key()]; ok {
				continue
			}
			args := []string{fam, "route", "del"}
			if cur.Type != "unicast" {
				args = append(args, cur.Type)
			}
			args = append(args, cur.Dst.String(), "table", cur.Table, "proto", RouteProto)
			if _, err := m.R.Run("ip", args...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, k := range sortedKeys(want) {
		r := want[k]
		args := []string{"route", "replace"}
		if r.Type != "unicast" {
			args = append(args, r.Type)
		}
		args = append(args, r.Dst.String())
		if r.Dev != "" {
			args = append(args, "dev", r.Dev)
		}
		args = append(args, "table", r.Table, "proto", RouteProto)
		if _, err := m.R.Run("ip", args...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func wantsFamily(fam string, prefixes func(func(netip.Prefix) bool)) bool {
	for p := range prefixes {
		if p.Addr().Is6() == (fam == "-6") {
			return true
		}
	}
	return false
}

func parseDst(s string, v6 bool) (netip.Prefix, bool) {
	if s == "default" {
		if v6 {
			return netip.MustParsePrefix("::/0"), true
		}
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	return p, err == nil
}

// Rule beschreibt eine Source Policy Rule.
type Rule struct {
	From  netip.Prefix
	Table string
}

// SyncRules setzt die Policy Rules mit der angegebenen Priorität exakt auf desired.
func (m *Manager) SyncRules(priority int, desired []Rule) error {
	prio := strconv.Itoa(priority)
	want := map[string]Rule{}
	for _, r := range desired {
		r.From = r.From.Masked()
		want[r.From.String()+"|"+r.Table] = r
	}
	var errs []error
	for _, fam := range []string{"-4", "-6"} {
		out, err := m.R.Query("ip", "-j", fam, "rule", "show")
		if err != nil {
			if wantsFamily(fam, func(yield func(netip.Prefix) bool) {
				for _, r := range want {
					if !yield(r.From) {
						return
					}
				}
			}) {
				errs = append(errs, err)
			}
			continue
		}
		var entries []struct {
			Priority int    `json:"priority"`
			Src      string `json:"src"`
			SrcLen   *int   `json:"srclen"`
			Table    any    `json:"table"`
		}
		if strings.TrimSpace(out) != "" {
			if err := json.Unmarshal([]byte(out), &entries); err != nil {
				errs = append(errs, fmt.Errorf("ip rule parsen: %w", err))
				continue
			}
		}
		for _, e := range entries {
			if e.Priority != priority || e.Src == "" || e.Src == "all" {
				continue
			}
			addr, err := netip.ParseAddr(e.Src)
			if err != nil {
				continue
			}
			bits := addr.BitLen()
			if e.SrcLen != nil {
				bits = *e.SrcLen
			}
			from := netip.PrefixFrom(addr, bits).Masked()
			table := fmt.Sprint(e.Table)
			if _, ok := want[from.String()+"|"+table]; ok {
				delete(want, from.String()+"|"+table)
				continue
			}
			if _, err := m.R.Run("ip", fam, "rule", "del", "priority", prio, "from", from.String(), "table", table); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, k := range sortedKeys(want) {
		r := want[k]
		if _, err := m.R.Run("ip", "rule", "add", "priority", prio, "from", r.From.String(), "table", r.Table); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LocalPlan berechnet für lokal zu registrierende Netze die Adressen (Hostadressen
// auf dem Dummy Interface) und AnyIP Routen (ganze Subnetze in der local Tabelle).
func LocalPlan(cidrs []netip.Prefix) (addrs []netip.Prefix, routes []Route) {
	for _, c := range cidrs {
		c = c.Masked()
		if c.Bits() == c.Addr().BitLen() {
			addrs = append(addrs, c)
			continue
		}
		routes = append(routes, Route{Type: "local", Dst: c, Dev: "lo", Table: "local"})
	}
	return addrs, routes
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
