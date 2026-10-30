package router

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tinybrickboy/router/internal/store"
)

var greName = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// validGREName prüft den Interface Namen eines GRE Tunnels. gre0 ist das
// Fallback Interface des Kernels und lässt sich nicht verwalten.
func validGREName(v string) bool { return greName.MatchString(v) && v != "gre0" }

// greInUse meldet, ob name bereits als GRE Tunnel konfiguriert ist.
func greInUse(st *store.State, name string) bool {
	for _, g := range st.Settings.GRE {
		if g.Name == name {
			return true
		}
	}
	return false
}

// parseGRE liest einen GRE Tunnel aus dem Formular. Beim Bearbeiten (old != nil)
// bleiben ID und Slot erhalten.
func parseGRE(r *http.Request, st *store.State, old *store.GRETunnel) (store.GRETunnel, error) {
	var g store.GRETunnel
	if old != nil {
		g = *old
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !validGREName(name) {
		return g, fmt.Errorf("interface name: 1 bis 15 zeichen a-z, 0-9 und -")
	}
	if name == st.Settings.WireGuard.Interface || name == st.Settings.System.DummyInterface {
		return g, fmt.Errorf("interface %s wird bereits verwendet", name)
	}
	local, err := netip.ParseAddr(strings.TrimSpace(r.FormValue("local")))
	if err != nil || !local.Is4() {
		return g, fmt.Errorf("lokale adresse muss eine ipv4 adresse sein")
	}
	remote, err := netip.ParseAddr(strings.TrimSpace(r.FormValue("remote")))
	if err != nil || !remote.Is4() || remote == local {
		return g, fmt.Errorf("remote adresse muss eine andere ipv4 adresse sein")
	}
	addr, err := netip.ParsePrefix(strings.TrimSpace(r.FormValue("address")))
	if err != nil || !addr.Addr().Is4() {
		return g, fmt.Errorf("tunneladresse muss ipv4 mit präfixlänge sein, z.b. 100.64.0.5/31")
	}
	mtu := store.GREDefaultMTU
	if v := strings.TrimSpace(r.FormValue("mtu")); v != "" {
		if mtu, err = atoi(v); err != nil || mtu < 576 || mtu > 9000 {
			return g, fmt.Errorf("mtu muss zwischen 576 und 9000 liegen")
		}
	}
	for _, o := range st.Settings.GRE {
		if old != nil && o.ID == old.ID {
			continue
		}
		if o.Name == name {
			return g, fmt.Errorf("gre tunnel %s existiert bereits", name)
		}
		// der Kernel erlaubt pro local/remote Paar nur einen Tunnel (ohne Key)
		if o.Local == local.String() && o.Remote == remote.String() {
			return g, fmt.Errorf("es gibt bereits einen tunnel %s → %s (%s)", local, remote, o.Name)
		}
	}
	g.Name, g.Local, g.Remote, g.Address, g.MTU = name, local.String(), remote.String(), addr.String(), mtu
	g.ReplyRouting = r.FormValue("reply_routing") != ""
	return g, nil
}

func (s *Server) greAdd(w http.ResponseWriter, r *http.Request) {
	name := ""
	err := s.Store.Update(func(st *store.State) error {
		g, err := parseGRE(r, st, nil)
		if err != nil {
			return err
		}
		if g.Slot, err = st.FreeGRESlot(); err != nil {
			return err
		}
		g.ID, name = store.NewID(), g.Name
		st.Settings.GRE = append(st.Settings.GRE, g)
		return nil
	})
	s.done(w, r, "/settings", err, "GRE Tunnel "+name+" hinzugefügt")
}

func (s *Server) greEdit(w http.ResponseWriter, r *http.Request) {
	name := ""
	err := s.Store.Update(func(st *store.State) error {
		for i := range st.Settings.GRE {
			if st.Settings.GRE[i].ID == r.PathValue("id") {
				g, err := parseGRE(r, st, &st.Settings.GRE[i])
				if err != nil {
					return err
				}
				st.Settings.GRE[i], name = g, g.Name
				return nil
			}
		}
		return fmt.Errorf("gre tunnel nicht gefunden")
	})
	s.done(w, r, "/settings", err, "GRE Tunnel "+name+" gespeichert")
}

func (s *Server) greDelete(w http.ResponseWriter, r *http.Request) {
	name := ""
	err := s.Store.Update(func(st *store.State) error {
		for i, g := range st.Settings.GRE {
			if g.ID == r.PathValue("id") {
				name = g.Name
				st.Settings.GRE = append(st.Settings.GRE[:i], st.Settings.GRE[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("gre tunnel nicht gefunden")
	})
	s.done(w, r, "/settings", err, "GRE Tunnel "+name+" gelöscht")
}
