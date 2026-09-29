// Package store verwaltet den persistenten Zustand des Routers als JSON Datei.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/tinybrickboy/router/internal/sysexec"
)

// TargetLocal bedeutet: das Netz wird direkt auf dem VPS registriert.
const TargetLocal = "local"

type State struct {
	Settings    Settings     `json:"settings"`
	Prefixes    []Prefix     `json:"prefixes"`
	Assignments []Assignment `json:"assignments"`
	Backends    []Backend    `json:"backends"`
	Admin       Admin        `json:"admin"`
	Users       []User       `json:"users"`
	// OIDCEpoch wird beim Abmelden eines OpenID Benutzers erhöht und beendet alle OpenID Sessions.
	OIDCEpoch    int    `json:"oidc_epoch"`
	WGPrivateKey string `json:"wg_private_key"`
	SecretKey    string `json:"secret_key"`
}

type Settings struct {
	ASN       uint32         `json:"asn"`
	RouterID  string         `json:"router_id"`
	PublicURL string         `json:"public_url"`
	IPv4      FamilySettings `json:"ipv4"`
	IPv6      FamilySettings `json:"ipv6"`
	WireGuard WGSettings     `json:"wireguard"`
	System    SystemSettings `json:"system"`
	Update    UpdateSettings `json:"update"`
	RPKI      RPKISettings   `json:"rpki"`
	OIDC      OIDCSettings   `json:"oidc"`
	// MetricsToken schützt /metrics (leer = Endpoint aus).
	MetricsToken string `json:"metrics_token"`
}

// OIDCSettings: Login über einen OpenID Connect Provider.
type OIDCSettings struct {
	Enabled         bool   `json:"enabled"`
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	AllowedUsers    string `json:"allowed_users"`  // E-Mail, Benutzername oder sub, kommagetrennt
	AllowedGroups   string `json:"allowed_groups"` // Werte aus dem groups Claim, kommagetrennt
	ViewerUsers     string `json:"viewer_users"`   // wie AllowedUsers, aber nur lesend
	ViewerGroups    string `json:"viewer_groups"`  // wie AllowedGroups, aber nur lesend
	DisablePassword bool   `json:"disable_password"`
}

// RPKISettings: optionaler RTR Validator. Ist er gesetzt, kündigt BIRD keine
// Präfixe an, die laut RPKI für die eigene ASN invalid sind.
type RPKISettings struct {
	RTRHost string `json:"rtr_host"`
	RTRPort int    `json:"rtr_port"`
}

type FamilySettings struct {
	Enabled   bool       `json:"enabled"`
	Neighbors []Neighbor `json:"neighbors"`
}

type Neighbor struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	RemoteASN     uint32 `json:"remote_asn"`
	Password      string `json:"password"`
	Multihop      int    `json:"multihop"`
	SourceAddress string `json:"source_address"`
}

type WGSettings struct {
	Interface  string `json:"interface"`
	ListenPort int    `json:"listen_port"`
	Endpoint   string `json:"endpoint"` // öffentliche IP/Hostname des VPS
	TunnelV4   string `json:"tunnel_v4"`
	TunnelV6   string `json:"tunnel_v6"`
	MTU        int    `json:"mtu"`
}

type SystemSettings struct {
	DummyInterface string `json:"dummy_interface"`
	ManageBird     bool   `json:"manage_bird"`
	BirdConfig     string `json:"bird_config"`
	BirdBinary     string `json:"bird_binary"`
	BirdcBinary    string `json:"birdc_binary"`
}

type UpdateSettings struct {
	GitHubRepo       string `json:"github_repo"`
	AutoUpdateAgents bool   `json:"auto_update_agents"`
}

type Prefix struct {
	ID          string `json:"id"`
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
	Announce    bool   `json:"announce"`
}

type Assignment struct {
	ID          string `json:"id"`
	CIDR        string `json:"cidr"`
	Target      string `json:"target"` // "local" oder Backend ID
	Description string `json:"description"`
}

type Backend struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Token           string `json:"token"`
	PublicKey       string `json:"public_key"`
	Hostname        string `json:"hostname"`
	TunnelV4        string `json:"tunnel_v4"`
	TunnelV6        string `json:"tunnel_v6"`
	UpdateRequested bool   `json:"update_requested"`
}

// Rollen: Admins dürfen alles, Viewer nur lesen.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Admin ist der Hauptbenutzer. Er ist immer Admin und kann nicht gelöscht werden.
type Admin = User

// User ist ein lokaler Benutzer mit Passwort.
type User struct {
	Username     string `json:"username"`
	Role         string `json:"role,omitempty"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	Iterations   int    `json:"iterations"`
	// SessionEpoch wird beim Abmelden erhöht und macht alle Sessions ungültig.
	SessionEpoch int `json:"session_epoch"`
}

// Defaults liefert einen neuen Zustand mit sinnvollen Standardwerten.
func Defaults() State {
	return State{
		Settings: Settings{
			ASN:  65000,
			IPv4: FamilySettings{Enabled: true},
			IPv6: FamilySettings{Enabled: true},
			WireGuard: WGSettings{
				Interface:  "wg-bgp",
				ListenPort: 51820,
				TunnelV4:   "10.200.0.0/24",
				TunnelV6:   "fd00:200::/64",
				MTU:        1420,
			},
			System: SystemSettings{
				DummyInterface: "bgp0",
				ManageBird:     true,
				BirdConfig:     "/etc/bird/bird.conf",
				BirdBinary:     "bird",
				BirdcBinary:    "birdc",
			},
			Update: UpdateSettings{GitHubRepo: "tinybrickboy/router"},
		},
		SecretKey: RandomHex(32),
	}
}

// Store ist threadsicher und speichert jede Änderung sofort.
type Store struct {
	path  string
	mu    sync.RWMutex
	state State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: Defaults()}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, s.save()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.state.SecretKey == "" {
		s.state.SecretKey = RandomHex(32)
	}
	return s, nil
}

// Get liefert eine tiefe Kopie des Zustands.
func (s *Store) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.state)
}

// Update ändert den Zustand. Liefert fn einen Fehler, wird nichts gespeichert.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	prev := s.state
	s.state = next
	if err := s.save(); err != nil {
		s.state = prev
		return err
	}
	return nil
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return sysexec.WriteFileAtomic(s.path, data, 0o600)
}

func clone(st State) State {
	data, _ := json.Marshal(st)
	var out State
	_ = json.Unmarshal(data, &out)
	return out
}

// RandomHex erzeugt n zufällige Bytes als Hex String.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewID erzeugt eine kurze ID.
func NewID() string { return RandomHex(6) }

// Backend sucht ein Backend per ID.
func (st *State) Backend(id string) *Backend {
	for i := range st.Backends {
		if st.Backends[i].ID == id {
			return &st.Backends[i]
		}
	}
	return nil
}

// User sucht einen lokalen Benutzer (inklusive Hauptbenutzer) per Name.
func (st *State) User(name string) *User {
	if name == "" {
		return nil
	}
	if st.Admin.Username == name {
		return &st.Admin
	}
	for i := range st.Users {
		if st.Users[i].Username == name {
			return &st.Users[i]
		}
	}
	return nil
}

// UserRole liefert die Rolle eines lokalen Benutzers.
func (st *State) UserRole(name string) string {
	if name == st.Admin.Username {
		return RoleAdmin
	}
	if u := st.User(name); u != nil && u.Role == RoleAdmin {
		return RoleAdmin
	}
	return RoleViewer
}

// RouterTunnelAddrs liefert die Tunneladressen des Routers (erste Hostadresse) mit Präfixlänge.
func (st *State) RouterTunnelAddrs() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{st.Settings.WireGuard.TunnelV4, st.Settings.WireGuard.TunnelV6} {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		p = p.Masked()
		out = append(out, netip.PrefixFrom(p.Addr().Next(), p.Bits()))
	}
	return out
}

// AllocateTunnelIPs vergibt allen Backends ohne (gültige) Tunnel IP eine freie Adresse.
func (st *State) AllocateTunnelIPs() error {
	alloc := func(subnet string, get func(*Backend) *string) error {
		if subnet == "" {
			for i := range st.Backends {
				*get(&st.Backends[i]) = ""
			}
			return nil
		}
		p, err := netip.ParsePrefix(subnet)
		if err != nil {
			return fmt.Errorf("Tunnelnetz %q: %w", subnet, err)
		}
		p = p.Masked()
		used := map[netip.Addr]bool{p.Addr(): true, p.Addr().Next(): true}
		for i := range st.Backends {
			ip := get(&st.Backends[i])
			if a, err := netip.ParseAddr(*ip); err == nil && p.Contains(a) && !used[a] {
				used[a] = true
			} else {
				*ip = ""
			}
		}
		for i := range st.Backends {
			ip := get(&st.Backends[i])
			if *ip != "" {
				continue
			}
			a := p.Addr()
			for used[a] {
				a = a.Next()
			}
			if !p.Contains(a) || (a.Is4() && a == lastV4(p)) {
				return fmt.Errorf("Tunnelnetz %s ist voll", p)
			}
			used[a] = true
			*ip = a.String()
		}
		return nil
	}
	if err := alloc(st.Settings.WireGuard.TunnelV4, func(b *Backend) *string { return &b.TunnelV4 }); err != nil {
		return err
	}
	return alloc(st.Settings.WireGuard.TunnelV6, func(b *Backend) *string { return &b.TunnelV6 })
}

func lastV4(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
