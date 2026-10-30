package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/tinybrickboy/router/internal/api"
	"github.com/tinybrickboy/router/internal/store"
)

// firewallNetwork liefert der Edge Firewall die Präfixe und Zuweisungen, damit
// sie pro IP Regeln anbieten und anzeigen kann, wohin eine IP geroutet wird.
// Zugriff nur mit dem Firewall Token (Authorization: Bearer <token>), nur lesend
// und ohne Geheimnisse. Ohne gesetztes Token ist der Endpoint aus.
func (s *Server) firewallNetwork(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Get()
	tok := st.Settings.FirewallToken
	if tok == "" {
		http.NotFound(w, r)
		return
	}
	if !constEq(bearer(r), tok) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="firewall"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	out := api.Network{Router: s.baseURL(st, r), ASN: st.Settings.ASN,
		Prefixes: []api.NetworkPrefix{}, Assignments: []api.NetworkAssignment{}}
	for _, p := range st.Prefixes {
		out.Prefixes = append(out.Prefixes, api.NetworkPrefix{CIDR: p.CIDR, Description: p.Description, Announce: p.Announce})
	}
	names := targetNames(st)
	for _, a := range st.Assignments {
		out.Assignments = append(out.Assignments, api.NetworkAssignment{
			CIDR: a.CIDR, Target: a.Target, TargetName: names[a.Target], Description: a.Description,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// settingsFirewall setzt die URL der Edge Firewall und erzeugt oder löscht das Token.
func (s *Server) settingsFirewall(w http.ResponseWriter, r *http.Request) {
	msg := "Edge Firewall Einstellungen gespeichert"
	err := s.Store.Update(func(st *store.State) error {
		switch r.FormValue("action") {
		case "generate":
			st.Settings.FirewallToken = store.RandomHex(24)
			msg = "Neues Firewall Token erzeugt, das alte ist ungültig"
			return nil
		case "disable":
			st.Settings.FirewallToken = ""
			msg = "Firewall API deaktiviert"
			return nil
		}
		v := strings.TrimRight(strings.TrimSpace(r.FormValue("firewall_url")), "/")
		if v != "" {
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				return fmt.Errorf("firewall url muss mit http:// oder https:// beginnen")
			}
		}
		st.Settings.FirewallURL = v
		return nil
	})
	s.done(w, r, "/settings", err, msg)
}
