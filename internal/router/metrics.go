package router

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/version"
)

// metricsWriter erzeugt das Prometheus Textformat.
type metricsWriter struct {
	b    strings.Builder
	seen map[string]bool
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

// add schreibt einen Wert. labels sind Paare aus Name und Wert.
func (m *metricsWriter) add(name, typ, help string, value float64, labels ...string) {
	if !m.seen[name] {
		m.seen[name] = true
		fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	m.b.WriteString(name)
	if len(labels) > 0 {
		m.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				m.b.WriteByte(',')
			}
			fmt.Fprintf(&m.b, `%s="%s"`, labels[i], promLabel(labels[i+1]))
		}
		m.b.WriteByte('}')
	}
	fmt.Fprintf(&m.b, " %g\n", value)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metrics liefert Kennzahlen für Prometheus. Zugriff nur mit dem Metrics Token
// (Authorization: Bearer <token>). Ohne gesetztes Token ist der Endpoint aus.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Get()
	tok := st.Settings.MetricsToken
	if tok == "" {
		http.NotFound(w, r)
		return
	}
	if !constEq(bearer(r), tok) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	m := &metricsWriter{seen: map[string]bool{}}
	m.add("bgp_router_info", "gauge", "Version des Routers.", 1, "version", version.Version)

	last, applyErr, _ := s.Applier.Status()
	m.add("bgp_router_apply_success", "gauge", "1 wenn das letzte Anwenden der Konfiguration erfolgreich war.", b2f(applyErr == nil && !last.IsZero()))
	if !last.IsZero() {
		m.add("bgp_router_apply_timestamp_seconds", "gauge", "Zeitpunkt des letzten Anwendens.", float64(last.Unix()))
	}

	if st.Settings.System.ManageBird {
		if sessions, err := s.bgpSessions(st.Settings.System.BirdcBinary); err == nil {
			for _, p := range sessions {
				m.add("bgp_router_bgp_session_up", "gauge", "1 wenn die BGP Session aufgebaut ist (Established).", b2f(p.Up()), "protocol", p.Name, "state", p.State)
			}
		}
	}

	for _, p := range st.Prefixes {
		m.add("bgp_router_prefix_announced", "gauge", "1 wenn das Präfix angekündigt werden soll.", b2f(p.Announce), "prefix", p.CIDR)
		if res, ok := s.rpki.get(st.Settings.ASN, p.CIDR); ok {
			m.add("bgp_router_prefix_rpki_valid", "gauge", "1 wenn das Präfix laut letzter Prüfung RPKI valid ist.", b2f(res.Status == "valid"), "prefix", p.CIDR, "status", res.Status)
		}
	}
	m.add("bgp_router_assignments", "gauge", "Anzahl der Zuweisungen.", float64(len(st.Assignments)))

	views := s.backendViews(st)
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	for _, b := range views {
		m.add("bgp_router_backend_online", "gauge", "1 wenn sich der Agent in den letzten 90 Sekunden gemeldet hat.", b2f(b.Online), "backend", b.Name)
		if !b.LastSeen.IsZero() {
			m.add("bgp_router_backend_last_seen_timestamp_seconds", "gauge", "Letzte Meldung des Agents.", float64(b.LastSeen.Unix()), "backend", b.Name)
		}
		m.add("bgp_router_backend_outdated", "gauge", "1 wenn für den Agent ein Update bereitliegt.", b2f(b.Outdated), "backend", b.Name)
		if b.WG != nil {
			m.add("bgp_router_wireguard_tunnel_up", "gauge", "1 wenn der letzte Handshake höchstens 3 Minuten her ist.", b2f(b.WG.TunnelUp()), "backend", b.Name)
			if !b.WG.Handshake.IsZero() {
				m.add("bgp_router_wireguard_latest_handshake_seconds", "gauge", "Zeitpunkt des letzten WireGuard Handshakes.", float64(b.WG.Handshake.Unix()), "backend", b.Name)
			}
			m.add("bgp_router_wireguard_received_bytes_total", "counter", "Vom Backend empfangene Bytes.", float64(b.WG.RX), "backend", b.Name)
			m.add("bgp_router_wireguard_sent_bytes_total", "counter", "Zum Backend gesendete Bytes.", float64(b.WG.TX), "backend", b.Name)
		}
	}
	m.add("bgp_router_scrape_timestamp_seconds", "gauge", "Zeitpunkt dieser Abfrage.", float64(time.Now().Unix()))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(m.b.String()))
}

func (s *Server) settingsMetrics(w http.ResponseWriter, r *http.Request) {
	enable := r.FormValue("action") == "generate"
	err := s.Store.Update(func(st *store.State) error {
		st.Settings.MetricsToken = ""
		if enable {
			st.Settings.MetricsToken = store.RandomHex(24)
		}
		return nil
	})
	msg := "Metrics Endpoint deaktiviert"
	if enable {
		msg = "Neues Metrics Token erzeugt"
	}
	s.done(w, r, "/settings", err, msg)
}
