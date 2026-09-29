// Package agent läuft auf den Backends: holt die Konfiguration vom Router,
// baut den WireGuard Tunnel auf und registriert die zugewiesenen IPs lokal.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/router/internal/api"
	"github.com/tinybrickboy/router/internal/netcfg"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/tlsutil"
	"github.com/tinybrickboy/router/internal/update"
	"github.com/tinybrickboy/router/internal/version"
	"github.com/tinybrickboy/router/internal/wgkey"
)

// Config ist die lokale Konfiguration des Agents (/etc/bgp-agent/config.json).
type Config struct {
	Server          string `json:"server"`
	Token           string `json:"token"`
	Interface       string `json:"interface"`
	DummyInterface  string `json:"dummy_interface"`
	Table           int    `json:"table"`
	RulePriority    int    `json:"rule_priority"`
	IntervalSeconds int    `json:"interval_seconds"`
	KeyFile         string `json:"key_file"`
	CacheFile       string `json:"cache_file"`
	// PinSHA256 ist der Public Key Hash des selbst signierten Router Zertifikats.
	PinSHA256 string `json:"pin_sha256"`
	// AllowInsecureUpdates erlaubt Selbst-Updates über HTTP ohne TLS (nicht empfohlen).
	AllowInsecureUpdates bool `json:"allow_insecure_updates"`
}

// LoadConfig liest die Konfiguration und setzt Standardwerte.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	if c.Interface == "" {
		c.Interface = "wg-bgp"
	}
	if c.DummyInterface == "" {
		c.DummyInterface = "bgp0"
	}
	if c.Table == 0 {
		c.Table = 51820
	}
	if c.RulePriority == 0 {
		c.RulePriority = 10200
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 30
	}
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(dir, "private.key")
	}
	if c.CacheFile == "" {
		c.CacheFile = filepath.Join(dir, "last-config.json")
	}
	c.Server = strings.TrimRight(c.Server, "/")
	if c.Server == "" || c.Token == "" {
		return c, errors.New("server und token müssen gesetzt sein")
	}
	return c, nil
}

type Agent struct {
	Cfg    Config
	Runner *sysexec.Runner
	client *http.Client
	priv   string
	pub    string
}

func New(cfg Config, r *sysexec.Runner) *Agent {
	return &Agent{Cfg: cfg, Runner: r, client: tlsutil.Client(cfg.PinSHA256, 20*time.Second)}
}

func (a *Agent) insecure() bool { return strings.HasPrefix(a.Cfg.Server, "http://") }

func (a *Agent) loadKey() error {
	data, err := os.ReadFile(a.Cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		priv, _, err := wgkey.Generate()
		if err != nil {
			return err
		}
		if err := sysexec.WriteFileAtomic(a.Cfg.KeyFile, []byte(priv+"\n"), 0o600); err != nil {
			return err
		}
		data = []byte(priv)
		log.Printf("neuer wireguard schlüssel erzeugt (%s)", a.Cfg.KeyFile)
	} else if err != nil {
		return err
	}
	a.priv = strings.TrimSpace(string(data))
	a.pub, err = wgkey.Public(a.priv)
	return err
}

// Run synchronisiert endlos. Die Netzwerkkonfiguration bleibt beim Beenden bestehen.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadKey(); err != nil {
		return err
	}
	log.Printf("bgp-agent %s gestartet, server %s, public key %s", version.Version, a.Cfg.Server, a.pub)
	if a.insecure() {
		log.Printf("WARNUNG: verbindung zum router ohne TLS, konfiguration kann unterwegs manipuliert werden")
	}
	first := true
	for {
		a.cycle(first)
		first = false
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(a.Cfg.IntervalSeconds) * time.Second):
		}
	}
}

// Once führt genau eine Synchronisation aus.
func (a *Agent) Once() error {
	if err := a.loadKey(); err != nil {
		return err
	}
	cfg, err := a.sync()
	if err != nil {
		return err
	}
	return a.apply(cfg)
}

func (a *Agent) cycle(first bool) {
	cfg, err := a.sync()
	if err != nil {
		log.Printf("synchronisation fehlgeschlagen: %v", err)
		if !first {
			return // aktuelle Konfiguration einfach beibehalten
		}
		// Nach einem Neustart ohne Router Verbindung die letzte bekannte Konfiguration nutzen
		data, rerr := os.ReadFile(a.Cfg.CacheFile)
		if rerr != nil || json.Unmarshal(data, &cfg) != nil {
			return
		}
		log.Printf("nutze zwischengespeicherte konfiguration")
	} else if data, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		_ = sysexec.WriteFileAtomic(a.Cfg.CacheFile, data, 0o600)
	}
	if err := a.apply(cfg); err != nil {
		log.Printf("anwenden: %v", err)
	}
	if cfg.Update != nil {
		if err := a.selfUpdate(cfg.Update); err != nil {
			log.Printf("update fehlgeschlagen: %v", err)
		}
	}
}

func (a *Agent) sync() (api.AgentConfig, error) {
	var cfg api.AgentConfig
	host, _ := os.Hostname()
	body, _ := json.Marshal(api.SyncRequest{
		PublicKey: a.pub, Hostname: host, Version: version.Version,
		SHA256: version.SelfSHA256(), Arch: runtime.GOARCH,
	})
	req, err := http.NewRequest(http.MethodPost, a.Cfg.Server+"/api/agent/sync", bytes.NewReader(body))
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return cfg, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, validateConfig(&cfg)
}

// validateConfig prüft die Werte vom Router, bevor sie als root angewendet werden.
func validateConfig(cfg *api.AgentConfig) error {
	if cfg.ServerPublicKey != "" && !wgkey.Valid(cfg.ServerPublicKey) {
		return errors.New("ungültiger server public key")
	}
	if cfg.Endpoint != "" {
		host, port, err := net.SplitHostPort(cfg.Endpoint)
		if err != nil || host == "" || strings.ContainsAny(cfg.Endpoint, " \t\r\n=#") {
			return fmt.Errorf("ungültiger endpoint %q", cfg.Endpoint)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("ungültiger endpoint port %q", port)
		}
	}
	if cfg.MTU != 0 && (cfg.MTU < 1280 || cfg.MTU > 9000) {
		return fmt.Errorf("ungültige mtu %d", cfg.MTU)
	}
	if cfg.Keepalive < 0 || cfg.Keepalive > 3600 {
		return fmt.Errorf("ungültiger keepalive %d", cfg.Keepalive)
	}
	for _, t := range cfg.TunnelAddrs {
		if _, err := netip.ParsePrefix(t); err != nil {
			return fmt.Errorf("ungültige tunnel adresse %q", t)
		}
	}
	for _, r := range cfg.Routes {
		p, err := netip.ParsePrefix(r)
		// niemals eine Default Route oder riesige Netze über den Tunnel lokal registrieren
		if err != nil || (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			return fmt.Errorf("ungültige zuweisung %q", r)
		}
	}
	if u := cfg.Update; u != nil {
		if !strings.HasPrefix(u.URL, "/download/bgp-agent-linux-") || strings.Contains(u.URL, "..") {
			return fmt.Errorf("ungültige update url %q", u.URL)
		}
		if len(u.SHA256) != 64 {
			return errors.New("ungültige update prüfsumme")
		}
	}
	return nil
}

func (a *Agent) apply(cfg api.AgentConfig) error {
	m := &netcfg.Manager{R: a.Runner}
	c := a.Cfg
	table := strconv.Itoa(c.Table)
	var errs []error
	add := func(step string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", step, err))
		}
	}

	// WireGuard Tunnel zum Router. AllowedIPs ist alles, das Routing
	// übernehmen wir selbst über eine eigene Tabelle.
	if err := m.EnsureLink(c.Interface, "wireguard", cfg.MTU); err != nil {
		add("wireguard interface", err)
	} else {
		wc := netcfg.WGConfig{PrivateKey: a.priv}
		if wgkey.Valid(cfg.ServerPublicKey) {
			wc.Peers = []netcfg.WGPeer{{
				PublicKey: cfg.ServerPublicKey, Endpoint: cfg.Endpoint,
				AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Keepalive: cfg.Keepalive,
			}}
		}
		add("wireguard", m.SyncWireGuard(c.Interface, filepath.Join(filepath.Dir(c.KeyFile), c.Interface+".conf"), wc))
		var tun []netip.Prefix
		for _, s := range cfg.TunnelAddrs {
			if p, err := netip.ParsePrefix(s); err == nil {
				tun = append(tun, p)
			}
		}
		add("tunnel adressen", m.SyncAddresses(c.Interface, tun))
		// Pakete an unsere IPs kommen über den Tunnel, der Rückweg zur Quelle
		// ginge aber übers normale Netz: strict rp_filter würde sie verwerfen.
		add("sysctl", m.Sysctl("net.ipv4.conf."+c.Interface+".rp_filter", "0"))
		if v, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter"); err == nil && strings.TrimSpace(string(v)) == "1" {
			add("sysctl", m.Sysctl("net.ipv4.conf.all.rp_filter", "2"))
		}
	}

	var nets []netip.Prefix
	for _, s := range cfg.Routes {
		if p, err := netip.ParsePrefix(s); err == nil {
			nets = append(nets, p.Masked())
		}
	}
	addrs, routes := netcfg.LocalPlan(nets)
	add("dummy interface", m.EnsureLink(c.DummyInterface, "dummy", 0))
	add("lokale adressen", m.SyncAddresses(c.DummyInterface, addrs))

	// Antworten von unseren IPs gehen über den Tunnel zurück (Policy Routing)
	var rules []netcfg.Rule
	has4, has6 := false, false
	for _, n := range nets {
		rules = append(rules, netcfg.Rule{From: n, Table: table})
		if n.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if has4 {
		routes = append(routes, netcfg.Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: c.Interface, Table: table})
	}
	if has6 {
		routes = append(routes, netcfg.Route{Dst: netip.MustParsePrefix("::/0"), Dev: c.Interface, Table: table})
	}
	add("routen", m.SyncRoutes(routes))
	add("policy rules", m.SyncRules(c.RulePriority, rules))
	return errors.Join(errs...)
}

func (a *Agent) selfUpdate(u *api.Update) error {
	if u.SHA256 == version.SelfSHA256() {
		return nil
	}
	if a.insecure() && !a.Cfg.AllowInsecureUpdates {
		// Ohne TLS könnte ein Angreifer im Netz Binary und Prüfsumme austauschen und root Code ausführen
		return errors.New("selbst-update über http abgelehnt: router mit https betreiben (oder allow_insecure_updates setzen)")
	}
	// validateConfig stellt sicher, dass die URL ein relativer Pfad auf den eigenen Router ist
	url := a.Cfg.Server + u.URL
	exe := update.Executable()
	tmp := exe + ".download"
	defer os.Remove(tmp)
	log.Printf("lade update %s", url)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := tlsutil.Client(a.Cfg.PinSHA256, 5*time.Minute)
	if _, err := update.Download(ctx, client, url, tmp, u.SHA256, nil); err != nil {
		return err
	}
	if err := update.Install(tmp, exe); err != nil {
		return err
	}
	log.Printf("update installiert (%s), starte neu", u.SHA256[:12])
	// Tunnel und Routen liegen im Kernel und bleiben während des exec aktiv
	return update.Reexec()
}

// Down entfernt die komplette Konfiguration des Agents.
func (a *Agent) Down() error {
	m := &netcfg.Manager{R: a.Runner}
	return errors.Join(
		m.SyncRules(a.Cfg.RulePriority, nil),
		m.SyncRoutes(nil),
		m.DeleteLink(a.Cfg.Interface),
		m.DeleteLink(a.Cfg.DummyInterface),
	)
}
