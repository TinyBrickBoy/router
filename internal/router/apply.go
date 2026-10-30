package router

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router/internal/netcfg"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/wgkey"
)

// Applier überträgt den gespeicherten Zustand auf das System.
type Applier struct {
	Store    *store.Store
	Runner   *sysexec.Runner
	StateDir string

	mu       sync.Mutex
	trigger  chan struct{}
	lastRun  time.Time
	lastErr  error
	lastBird string
	statusMu sync.RWMutex
}

func NewApplier(st *store.Store, r *sysexec.Runner, stateDir string) *Applier {
	return &Applier{Store: st, Runner: r, StateDir: stateDir, trigger: make(chan struct{}, 1)}
}

// Trigger fordert ein (entprelltes) Anwenden im Hintergrund an.
func (a *Applier) Trigger() {
	select {
	case a.trigger <- struct{}{}:
	default:
	}
}

// Loop wendet bei Änderungen und alle 5 Minuten (Selbstheilung) an.
func (a *Applier) Loop() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	a.Apply()
	for {
		select {
		case <-a.trigger:
			time.Sleep(300 * time.Millisecond)
		case <-tick.C:
		}
		a.Apply()
	}
}

// Status liefert Zeitpunkt, Fehler und zuletzt erzeugte BIRD Konfiguration.
func (a *Applier) Status() (time.Time, error, string) {
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()
	return a.lastRun, a.lastErr, a.lastBird
}

// Apply führt die komplette Konfiguration aus.
func (a *Applier) Apply() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.Store.Get()
	bird, err := a.apply(st)
	if err != nil {
		log.Printf("anwenden: %v", err)
	}
	a.statusMu.Lock()
	a.lastRun, a.lastErr = time.Now(), err
	if bird != "" {
		a.lastBird = bird
	}
	a.statusMu.Unlock()
	return err
}

func (a *Applier) apply(st store.State) (string, error) {
	s := st.Settings
	m := &netcfg.Manager{R: a.Runner}
	var errs []error
	add := func(step string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", step, err))
		}
	}

	if s.IPv4.Enabled {
		add("sysctl", m.Sysctl("net.ipv4.ip_forward", "1"))
	}
	if s.IPv6.Enabled {
		add("sysctl", m.Sysctl("net.ipv6.conf.all.forwarding", "1"))
	}

	var routes []netcfg.Route
	// Nicht zugewiesene Adressen der Präfixe sollen nicht zurück ins Internet laufen.
	for _, p := range st.Prefixes {
		if pfx, err := netip.ParsePrefix(p.CIDR); err == nil {
			routes = append(routes, netcfg.Route{Type: "unreachable", Dst: pfx})
		}
	}

	// Lokale Zuweisungen
	var local []netip.Prefix
	for _, as := range st.Assignments {
		if as.Target != store.TargetLocal {
			continue
		}
		if p, err := netip.ParsePrefix(as.CIDR); err == nil {
			local = append(local, p)
		}
	}
	addrs, localRoutes := netcfg.LocalPlan(local)
	routes = append(routes, localRoutes...)
	dummy := s.System.DummyInterface
	add("dummy interface", m.EnsureLink(dummy, "dummy", 0))
	add("lokale adressen", m.SyncAddresses(dummy, addrs))

	// WireGuard
	wg := s.WireGuard
	if st.WGPrivateKey != "" && wg.Interface != "" {
		cfg := netcfg.WGConfig{PrivateKey: st.WGPrivateKey, ListenPort: wg.ListenPort}
		var forwarded []netip.Prefix
		for _, b := range st.Backends {
			if !wgkey.Valid(b.PublicKey) {
				continue
			}
			allowed := []string{}
			for _, ip := range []string{b.TunnelV4, b.TunnelV6} {
				if a, err := netip.ParseAddr(ip); err == nil {
					allowed = append(allowed, netip.PrefixFrom(a, a.BitLen()).String())
				}
			}
			for _, as := range st.Assignments {
				if as.Target != b.ID {
					continue
				}
				p, err := netip.ParsePrefix(as.CIDR)
				if err != nil {
					continue
				}
				allowed = append(allowed, p.Masked().String())
				routes = append(routes, netcfg.Route{Dst: p, Dev: wg.Interface})
				forwarded = append(forwarded, p)
			}
			cfg.Peers = append(cfg.Peers, netcfg.WGPeer{PublicKey: b.PublicKey, AllowedIPs: allowed})
		}
		if err := m.EnsureLink(wg.Interface, "wireguard", wg.MTU); err != nil {
			add("wireguard interface", err)
		} else {
			add("wireguard", m.SyncWireGuard(wg.Interface, filepath.Join(a.StateDir, wg.Interface+".conf"), cfg))
			add("wireguard adressen", m.SyncAddresses(wg.Interface, st.RouterTunnelAddrs()))
		}
		if s.IPv4.Enabled {
			add("forward freigabe", m.SyncForward("iptables", wg.Interface, forwarded))
		}
		if s.IPv6.Enabled {
			add("forward freigabe", m.SyncForward("ip6tables", wg.Interface, forwarded))
		}
	}

	routes = append(routes, a.applyGRE(m, s.GRE, add)...)

	add("routen", m.SyncRoutes(routes))

	var bird string
	if s.System.ManageBird {
		var err error
		bird, err = GenerateBird(st)
		if err != nil {
			add("bird", err)
		} else {
			add("bird", a.applyBird(s.System, bird))
		}
	}
	return bird, errors.Join(errs...)
}

// greTunnel prüft einen GRE Tunnel aus den Einstellungen.
func greTunnel(g store.GRETunnel) (netcfg.GRETunnel, error) {
	t := netcfg.GRETunnel{Name: g.Name, MTU: g.MTU}
	var err error
	if !validGREName(g.Name) {
		return t, fmt.Errorf("ungültiger interface name")
	}
	if t.Local, err = netip.ParseAddr(g.Local); err != nil || !t.Local.Is4() {
		return t, fmt.Errorf("lokale adresse muss ipv4 sein")
	}
	if t.Remote, err = netip.ParseAddr(g.Remote); err != nil || !t.Remote.Is4() {
		return t, fmt.Errorf("remote adresse muss ipv4 sein")
	}
	if t.Address, err = netip.ParsePrefix(g.Address); err != nil || !t.Address.Addr().Is4() {
		return t, fmt.Errorf("tunneladresse muss ipv4 mit präfixlänge sein")
	}
	if t.MTU == 0 {
		t.MTU = store.GREDefaultMTU
	}
	if g.ReplyRouting {
		if g.Slot < 1 || g.Slot > netcfg.GREMaxSlots {
			return t, fmt.Errorf("ungültiger slot %d", g.Slot)
		}
		t.Mark = netcfg.GREMark(g.Slot)
	}
	return t, nil
}

// applyGRE richtet die GRE Tunnel ein, inklusive MSS Clamping und Reply
// Routing, und liefert die Routen der Reply Tabellen.
func (a *Applier) applyGRE(m *netcfg.Manager, cfg []store.GRETunnel, add func(string, error)) []netcfg.Route {
	var keep []string
	for _, g := range cfg {
		keep = append(keep, g.Name)
	}
	// zuerst aufräumen: ein umbenannter Tunnel mit gleichem local/remote ließe sich sonst nicht anlegen
	add("gre aufräumen", m.RemoveStaleGRE(keep))

	var tunnels []netcfg.GRETunnel
	var rules []netcfg.MarkRule
	var routes []netcfg.Route
	for _, g := range cfg {
		t, err := greTunnel(g)
		if err != nil {
			add("gre "+g.Name, err)
			continue
		}
		tunnels = append(tunnels, t)
		if err := m.EnsureGRE(t); err != nil {
			add("gre "+g.Name, err)
			continue
		}
		if t.Mark == 0 {
			continue
		}
		table := netcfg.GRETable(g.Slot)
		rules = append(rules, netcfg.MarkRule{Mark: t.Mark, Mask: netcfg.GREMarkMask, Table: table})
		r := netcfg.Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: t.Name, Table: table}
		if peer, ok := netcfg.GREPeer(t.Address); ok {
			r.Via = peer
		}
		routes = append(routes, r)
	}
	add("gre reply routing", m.SyncMarkRules(netcfg.GRERulePriority, rules))
	add("gre firewall", m.SyncGREFirewall(filepath.Join(a.StateDir, "gre.nft"), tunnels))
	return routes
}

func (a *Applier) applyBird(sys store.SystemSettings, conf string) error {
	if a.Runner.DryRun {
		return a.Runner.WriteFile(sys.BirdConfig, []byte(conf), 0o640)
	}
	if old, err := os.ReadFile(sys.BirdConfig); err == nil && string(old) == conf {
		return nil
	}
	tmp := filepath.Join(a.StateDir, "bird.conf.check")
	if err := os.WriteFile(tmp, []byte(conf), 0o640); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := a.Runner.Run(sys.BirdBinary, "-p", "-c", tmp); err != nil {
		return fmt.Errorf("konfiguration ungültig: %w", err)
	}
	if err := a.Runner.WriteFile(sys.BirdConfig, []byte(conf), 0o640); err != nil {
		return err
	}
	out, err := a.Runner.Run(sys.BirdcBinary, "configure")
	if err != nil {
		return err
	}
	if strings.Contains(out, "rror") {
		return errors.New(strings.TrimSpace(out))
	}
	return nil
}

func netcfgManager(r *sysexec.Runner) *netcfg.Manager { return &netcfg.Manager{R: r} }

// Lock blockiert das Anwenden (z.B. während eines Neustarts).
func (a *Applier) Lock() { a.mu.Lock() }

// Unlock gibt das Anwenden wieder frei.
func (a *Applier) Unlock() { a.mu.Unlock() }
