// Package router enthält die WebUI und Steuerlogik für den BGP VPS.
package router

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/version"
)

//go:embed web
var webFS embed.FS

// Server ist die WebUI und API des Routers.
type Server struct {
	Store    *store.Store
	Applier  *Applier
	Runner   *sysexec.Runner
	DistDir  string
	StateDir string
	// Pin ist der Public Key Hash des selbst signierten Zertifikats (leer bei CA Zertifikat oder HTTP).
	Pin string
	// Restart ersetzt den Prozess durch das neu installierte Binary (ohne Downtime).
	Restart func() error

	tmpl map[string]*template.Template

	seenMu sync.RWMutex
	seen   map[string]agentSeen

	distMu    sync.Mutex
	distCache map[string]distEntry

	updateMu sync.Mutex

	rpki   rpkiCache
	oidc   oidcClient
	logins loginLimiter
	pins   pinCache
}

type agentSeen struct {
	At      time.Time
	Addr    string
	Version string
	SHA     string
	Arch    string
}

// Handler liefert den HTTP Handler.
func (s *Server) Handler() http.Handler {
	s.seen = map[string]agentSeen{}
	s.distCache = map[string]distEntry{}
	s.rpki.m = map[string]RPKIResult{}
	s.parseTemplates()

	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /auth/login", s.oidcLogin)
	mux.HandleFunc("GET /auth/callback", s.oidcCallback)

	a := s.requireAuth
	mux.HandleFunc("GET /{$}", a(s.dashboard))
	mux.HandleFunc("POST /apply", a(s.applyNow))

	mux.HandleFunc("GET /prefixes", a(s.prefixesPage))
	mux.HandleFunc("POST /prefixes", a(s.prefixAdd))
	mux.HandleFunc("POST /prefixes/{id}/toggle", a(s.prefixToggle))
	mux.HandleFunc("POST /prefixes/{id}/delete", a(s.prefixDelete))
	mux.HandleFunc("POST /prefixes/rpki", a(s.rpkiCheckAll))

	mux.HandleFunc("GET /assignments", a(s.assignmentsPage))
	mux.HandleFunc("POST /assignments", a(s.assignmentAdd))
	mux.HandleFunc("POST /assignments/{id}/target", a(s.assignmentTarget))
	mux.HandleFunc("POST /assignments/{id}/delete", a(s.assignmentDelete))

	mux.HandleFunc("GET /backends", a(s.backendsPage))
	mux.HandleFunc("POST /backends", a(s.backendAdd))
	mux.HandleFunc("POST /backends/{id}/delete", a(s.backendDelete))
	mux.HandleFunc("POST /backends/{id}/token", a(s.backendToken))
	mux.HandleFunc("POST /backends/{id}/update", a(s.backendUpdate))

	mux.HandleFunc("GET /settings", a(s.settingsPage))
	mux.HandleFunc("POST /settings/general", a(s.settingsGeneral))
	mux.HandleFunc("POST /settings/family/{fam}", a(s.settingsFamily))
	mux.HandleFunc("POST /settings/neighbors/{fam}", a(s.neighborAdd))
	mux.HandleFunc("POST /settings/neighbors/{fam}/{id}/delete", a(s.neighborDelete))
	mux.HandleFunc("POST /settings/wireguard", a(s.settingsWireGuard))
	mux.HandleFunc("POST /settings/system", a(s.settingsSystem))
	mux.HandleFunc("POST /settings/rpki", a(s.settingsRPKI))
	mux.HandleFunc("POST /settings/oidc", a(s.settingsOIDC))
	mux.HandleFunc("POST /settings/password", a(s.settingsPassword))

	mux.HandleFunc("GET /updates", a(s.updatesPage))
	mux.HandleFunc("POST /updates/settings", a(s.updateSettings))
	mux.HandleFunc("POST /updates/upload", a(s.updateUpload))
	mux.HandleFunc("POST /updates/github", a(s.updateGitHub))
	mux.HandleFunc("POST /updates/agents", a(s.updateAllAgents))
	mux.HandleFunc("POST /updates/rollback", a(s.updateRollback))

	// Öffentliche Endpunkte für die Backends (Token geschützt)
	mux.HandleFunc("GET /setup/{token}", s.setupScript)
	mux.HandleFunc("GET /download/{file}", s.download)
	mux.HandleFunc("POST /api/agent/sync", s.agentSync)

	return securityHeaders(mux)
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) parseTemplates() {
	funcs := template.FuncMap{
		"short": func(k string) string {
			if len(k) > 12 {
				return k[:12] + "…"
			}
			return k
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "nie"
			}
			d := time.Since(t).Round(time.Second)
			switch {
			case d < time.Minute:
				return fmt.Sprintf("vor %ds", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("vor %d min", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("vor %d h", int(d.Hours()))
			}
			return t.Format("02.01.2006 15:04")
		},
		"isV6": func(c string) bool { return strings.Contains(c, ":") },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
	s.tmpl = map[string]*template.Template{}
	pages, _ := fs.Glob(webFS, "web/templates/*.html")
	for _, p := range pages {
		name := strings.TrimSuffix(p[len("web/templates/"):], ".html")
		if name == "layout" {
			continue
		}
		s.tmpl[name] = template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "web/templates/layout.html", p))
	}
}

type page struct {
	Title   string
	Active  string
	CSRF    string
	Msg     string
	Err     string
	S       store.State
	Version string
	DryRun  bool

	// Übersicht
	LastApply  time.Time
	ApplyErr   string
	BirdConf   string
	BirdStatus string
	WGStatus   string
	Online     int

	Targets  map[string]string
	OIDC     bool
	PWLogin  bool
	Callback string
	RPKI     map[string]RPKIResult
	Backends []backendView
	Updates  *updatesView
}

func (s *Server) newPage(r *http.Request, title, active string) *page {
	st := s.Store.Get()
	return &page{
		Title: title, Active: active, CSRF: csrfToken(st, r),
		Msg: r.URL.Query().Get("msg"), Err: r.URL.Query().Get("err"),
		S: st, Version: version.Version, DryRun: s.Runner.DryRun,
	}
}

func (s *Server) render(w http.ResponseWriter, name string, p *page) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "template fehlt", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

// done leitet nach einer Aktion zurück und stößt das Anwenden an.
func (s *Server) done(w http.ResponseWriter, r *http.Request, back string, err error, msg string) {
	q := url.Values{}
	if err != nil {
		q.Set("err", err.Error())
	} else {
		if msg != "" {
			q.Set("msg", msg)
		}
		s.Applier.Trigger()
	}
	if len(q) > 0 {
		back += "?" + q.Encode()
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---------- Login ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	o := s.Store.Get().Settings.OIDC
	p := &page{Title: "Anmelden", Err: r.URL.Query().Get("err"), Version: version.Version,
		OIDC: o.Enabled, PWLogin: !(o.Enabled && o.DisablePassword)}
	s.render(w, "login", p)
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	st := s.Store.Get()
	if st.Settings.OIDC.Enabled && st.Settings.OIDC.DisablePassword {
		http.Error(w, "passwort login ist deaktiviert", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	if s.logins.Blocked(ip) {
		log.Printf("login von %s gesperrt (zu viele fehlversuche)", ip)
		http.Redirect(w, r, "/login?err="+url.QueryEscape("Zu viele fehlgeschlagene Anmeldungen, bitte in 15 Minuten erneut versuchen"), http.StatusSeeOther)
		return
	}
	user := r.FormValue("username")
	if constEq(user, st.Admin.Username) && checkPassword(st.Admin, r.FormValue("password")) {
		s.logins.Reset(ip)
		s.setSessionCookie(w, r, newSession(st), int(sessionTTL.Seconds()))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.logins.Fail(ip)
	log.Printf("fehlgeschlagener login von %s", ip)
	time.Sleep(time.Second)
	http.Redirect(w, r, "/login?err="+url.QueryEscape("Benutzername oder Passwort falsch"), http.StatusSeeOther)
}

func constEq(a, b string) bool { return len(a) == len(b) && mac("x", a) == mac("x", b) }

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// Alle Sessions serverseitig ungültig machen (auch gestohlene Cookies)
	if err := s.Store.Update(func(st *store.State) error { st.Admin.SessionEpoch++; return nil }); err != nil {
		log.Printf("logout: %v", err)
	}
	s.setSessionCookie(w, r, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- Übersicht ----------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Übersicht", "dash")
	last, err, bird := s.Applier.Status()
	p.LastApply, p.BirdConf = last, bird
	if err != nil {
		p.ApplyErr = err.Error()
	}
	if p.S.Settings.System.ManageBird {
		out, err := s.Runner.Query(p.S.Settings.System.BirdcBinary, "show", "protocols")
		if err != nil {
			out = err.Error()
		}
		p.BirdStatus = out
	}
	out, err := s.Runner.Query("wg", "show", p.S.Settings.WireGuard.Interface)
	if err != nil {
		out = err.Error()
	}
	p.WGStatus = out
	p.Backends = s.backendViews(p.S)
	for _, b := range p.Backends {
		if b.Online {
			p.Online++
		}
	}
	s.render(w, "dashboard", p)
}

func (s *Server) applyNow(w http.ResponseWriter, r *http.Request) {
	err := s.Applier.Apply()
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Konfiguration angewendet"), http.StatusSeeOther)
}

// ---------- Präfixe ----------

func (s *Server) prefixesPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Präfixe", "prefixes")
	p.RPKI = map[string]RPKIResult{}
	for _, pf := range p.S.Prefixes {
		if res, ok := s.rpki.get(p.S.Settings.ASN, pf.CIDR); ok {
			p.RPKI[pf.CIDR] = res
		}
	}
	s.render(w, "prefixes", p)
}

// parseCIDR akzeptiert auch einzelne Adressen (werden zu /32 bzw. /128).
func parseCIDR(v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q ist kein gültiges netz", v)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q ist kein gültiges netz", v)
	}
	return p.Masked(), nil
}

func (s *Server) prefixAdd(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		p, err := parseCIDR(r.FormValue("cidr"))
		if err != nil {
			return err
		}
		// Schutz vor Tippfehlern wie 0.0.0.0/0: das würde eine Default Route ankündigen
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			return fmt.Errorf("%s ist zu groß (mindestens /8 bzw. /16)", p)
		}
		if !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() {
			return fmt.Errorf("%s ist kein öffentliches unicast netz", p)
		}
		desc, err := cleanText("beschreibung", r.FormValue("description"), 200)
		if err != nil {
			return err
		}
		for _, o := range st.Prefixes {
			if op, err := netip.ParsePrefix(o.CIDR); err == nil && op.Overlaps(p) {
				return fmt.Errorf("%s überschneidet sich mit %s", p, op)
			}
		}
		st.Prefixes = append(st.Prefixes, store.Prefix{
			ID: store.NewID(), CIDR: p.String(), Description: desc,
			Announce: r.FormValue("announce") != "",
		})
		sort.Slice(st.Prefixes, func(i, j int) bool { return st.Prefixes[i].CIDR < st.Prefixes[j].CIDR })
		return nil
	})
	s.done(w, r, "/prefixes", err, "Präfix hinzugefügt")
}

func (s *Server) prefixToggle(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		for i := range st.Prefixes {
			if st.Prefixes[i].ID == r.PathValue("id") {
				st.Prefixes[i].Announce = !st.Prefixes[i].Announce
				return nil
			}
		}
		return fmt.Errorf("präfix nicht gefunden")
	})
	s.done(w, r, "/prefixes", err, "Gespeichert")
}

func (s *Server) prefixDelete(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		for i, p := range st.Prefixes {
			if p.ID != r.PathValue("id") {
				continue
			}
			pfx, _ := netip.ParsePrefix(p.CIDR)
			for _, a := range st.Assignments {
				if ap, err := netip.ParsePrefix(a.CIDR); err == nil && pfx.Overlaps(ap) {
					return fmt.Errorf("zuerst die zuweisung %s löschen", a.CIDR)
				}
			}
			st.Prefixes = append(st.Prefixes[:i], st.Prefixes[i+1:]...)
			return nil
		}
		return fmt.Errorf("präfix nicht gefunden")
	})
	s.done(w, r, "/prefixes", err, "Präfix gelöscht")
}

// ---------- Zuweisungen ----------

func targetNames(st store.State) map[string]string {
	m := map[string]string{store.TargetLocal: "Lokal (VPS)"}
	for _, b := range st.Backends {
		m[b.ID] = "WireGuard → " + b.Name
	}
	return m
}

func (s *Server) assignmentsPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Zuweisungen", "assignments")
	p.Targets = targetNames(p.S)
	s.render(w, "assignments", p)
}

func validTarget(st *store.State, t string) error {
	if t == store.TargetLocal || st.Backend(t) != nil {
		return nil
	}
	return fmt.Errorf("unbekanntes ziel")
}

func (s *Server) assignmentAdd(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		a, err := parseCIDR(r.FormValue("cidr"))
		if err != nil {
			return err
		}
		inside := false
		for _, p := range st.Prefixes {
			if pp, err := netip.ParsePrefix(p.CIDR); err == nil && pp.Bits() <= a.Bits() && pp.Contains(a.Addr()) {
				inside = true
			}
		}
		if !inside {
			return fmt.Errorf("%s liegt in keinem eingetragenen präfix", a)
		}
		for _, o := range st.Assignments {
			if op, err := netip.ParsePrefix(o.CIDR); err == nil && op.Overlaps(a) {
				return fmt.Errorf("%s überschneidet sich mit der zuweisung %s", a, op)
			}
		}
		t := r.FormValue("target")
		if err := validTarget(st, t); err != nil {
			return err
		}
		desc, err := cleanText("beschreibung", r.FormValue("description"), 200)
		if err != nil {
			return err
		}
		st.Assignments = append(st.Assignments, store.Assignment{
			ID: store.NewID(), CIDR: a.String(), Target: t, Description: desc,
		})
		sort.Slice(st.Assignments, func(i, j int) bool { return st.Assignments[i].CIDR < st.Assignments[j].CIDR })
		return nil
	})
	s.done(w, r, backTo(r, "/assignments"), err, "Zuweisung hinzugefügt")
}

func (s *Server) assignmentTarget(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		t := r.FormValue("target")
		if err := validTarget(st, t); err != nil {
			return err
		}
		for i := range st.Assignments {
			if st.Assignments[i].ID == r.PathValue("id") {
				st.Assignments[i].Target = t
				return nil
			}
		}
		return fmt.Errorf("zuweisung nicht gefunden")
	})
	s.done(w, r, "/assignments", err, "Ziel geändert")
}

func (s *Server) assignmentDelete(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		for i := range st.Assignments {
			if st.Assignments[i].ID == r.PathValue("id") {
				st.Assignments = append(st.Assignments[:i], st.Assignments[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("zuweisung nicht gefunden")
	})
	s.done(w, r, backTo(r, "/assignments"), err, "Zuweisung gelöscht")
}

// backTo erlaubt Formularen auf der Backend Seite, dorthin zurückzukehren.
func backTo(r *http.Request, def string) string {
	if r.URL.Query().Get("back") == "backends" {
		return "/backends"
	}
	return def
}

// ---------- Backends ----------

type backendView struct {
	store.Backend
	Online      bool
	LastSeen    time.Time
	Addr        string
	Version     string
	Arch        string
	Outdated    bool
	SetupCmd    string
	Assignments []store.Assignment
}

func (s *Server) baseURL(st store.State, r *http.Request) string {
	if st.Settings.PublicURL != "" {
		return strings.TrimRight(st.Settings.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// setupCommand pinnt beim selbst signierten Zertifikat den Public Key des Routers,
// damit schon das Setup Skript nicht per MITM ausgetauscht werden kann.
// Hinter einem Reverse Proxy mit CA Zertifikat wird normal gegen die CA geprüft.
func (s *Server) setupCommand(base, token string) string {
	u := base + "/setup/" + token
	if pin := s.pinFor(base); pin != "" {
		return fmt.Sprintf("curl -fsSLk --pinnedpubkey %s %s | sudo bash", shq("sha256//"+pin), shq(u))
	}
	return fmt.Sprintf("curl -fsSL %s | sudo bash", shq(u))
}

func (s *Server) backendViews(st store.State) []backendView {
	s.seenMu.RLock()
	defer s.seenMu.RUnlock()
	var out []backendView
	for _, b := range st.Backends {
		v := backendView{Backend: b}
		if seen, ok := s.seen[b.ID]; ok {
			v.LastSeen, v.Addr, v.Version, v.Arch = seen.At, seen.Addr, seen.Version, seen.Arch
			v.Online = time.Since(seen.At) < 90*time.Second
			if want, err := s.distSum(agentFile(seen.Arch)); err == nil && want != seen.SHA {
				v.Outdated = true
			}
		}
		for _, a := range st.Assignments {
			if a.Target == b.ID {
				v.Assignments = append(v.Assignments, a)
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) backendsPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Backends", "backends")
	p.Backends = s.backendViews(p.S)
	base := s.baseURL(p.S, r)
	for i := range p.Backends {
		// Das Kommando enthält das geheime Token: bei laufendem Agent nicht ausliefern
		if !p.Backends[i].Online {
			p.Backends[i].SetupCmd = s.setupCommand(base, p.Backends[i].Token)
		}
	}
	s.render(w, "backends", p)
}

func (s *Server) backendAdd(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		name, err := cleanText("name", r.FormValue("name"), 64)
		if err != nil {
			return err
		}
		if name == "" {
			return fmt.Errorf("name fehlt")
		}
		st.Backends = append(st.Backends, store.Backend{ID: store.NewID(), Name: name, Token: store.RandomHex(24)})
		return st.AllocateTunnelIPs()
	})
	s.done(w, r, "/backends", err, "Backend angelegt, jetzt das Setup Kommando auf dem Backend ausführen")
}

func (s *Server) backendDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.Store.Update(func(st *store.State) error {
		for _, a := range st.Assignments {
			if a.Target == id {
				return fmt.Errorf("backend hat noch zuweisungen (%s)", a.CIDR)
			}
		}
		for i := range st.Backends {
			if st.Backends[i].ID == id {
				st.Backends = append(st.Backends[:i], st.Backends[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("backend nicht gefunden")
	})
	s.done(w, r, "/backends", err, "Backend gelöscht")
}

func (s *Server) backendToken(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		b := st.Backend(r.PathValue("id"))
		if b == nil {
			return fmt.Errorf("backend nicht gefunden")
		}
		b.Token = store.RandomHex(24)
		return nil
	})
	s.done(w, r, "/backends", err, "Neues Token erzeugt, das alte ist ungültig")
}

// ---------- Einstellungen ----------

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Einstellungen", "settings")
	p.Callback = s.redirectURI(p.S, r)
	s.render(w, "settings", p)
}

// cleanText lehnt Steuerzeichen ab (z.B. Zeilenumbrüche in BIRD/WireGuard Configs) und begrenzt die Länge.
func cleanText(field, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return "", fmt.Errorf("%s ist zu lang (max. %d zeichen)", field, max)
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%s enthält ungültige zeichen", field)
		}
	}
	return v, nil
}

// validHost prüft einen Hostnamen oder eine IP (ohne Port).
func validHost(v string) bool {
	if _, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		return true
	}
	if v == "" || len(v) > 253 {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func atoi(v string) (int, error) {
	var n int
	_, err := fmt.Sscan(strings.TrimSpace(v), &n)
	return n, err
}

func parseASN(v string) (uint32, error) {
	v = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v)), "AS")
	var n uint64
	if _, err := fmt.Sscan(v, &n); err != nil || n == 0 || n > 4294967295 {
		return 0, fmt.Errorf("ungültige ASN %q", v)
	}
	return uint32(n), nil
}

func (s *Server) settingsGeneral(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		asn, err := parseASN(r.FormValue("asn"))
		if err != nil {
			return err
		}
		rid := strings.TrimSpace(r.FormValue("router_id"))
		if a, err := netip.ParseAddr(rid); err != nil || !a.Is4() {
			return fmt.Errorf("router id muss eine ipv4 adresse sein")
		}
		pub := strings.TrimRight(strings.TrimSpace(r.FormValue("public_url")), "/")
		if pub != "" {
			u, err := url.Parse(pub)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("öffentliche url muss mit http:// oder https:// beginnen")
			}
		}
		st.Settings.ASN, st.Settings.RouterID, st.Settings.PublicURL = asn, rid, pub
		return nil
	})
	s.done(w, r, "/settings", err, "Allgemeine Einstellungen gespeichert")
}

func family(st *store.State, fam string) (*store.FamilySettings, bool, error) {
	switch fam {
	case "ipv4":
		return &st.Settings.IPv4, false, nil
	case "ipv6":
		return &st.Settings.IPv6, true, nil
	}
	return nil, false, fmt.Errorf("unbekannte familie")
}

func (s *Server) settingsFamily(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		f, _, err := family(st, r.PathValue("fam"))
		if err != nil {
			return err
		}
		f.Enabled = r.FormValue("enabled") != ""
		return nil
	})
	s.done(w, r, "/settings", err, "Gespeichert")
}

func (s *Server) neighborAdd(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		f, v6, err := family(st, r.PathValue("fam"))
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(r.FormValue("address")))
		if err != nil || addr.Is6() != v6 {
			return fmt.Errorf("neighbor adresse passt nicht zur adressfamilie")
		}
		asn, err := parseASN(r.FormValue("remote_asn"))
		if err != nil {
			return err
		}
		name, err := cleanText("name", r.FormValue("name"), 64)
		if err != nil {
			return err
		}
		pw, err := cleanText("bgp passwort", r.FormValue("password"), 80)
		if err != nil {
			return err
		}
		n := store.Neighbor{
			ID: store.NewID(), Name: name, Address: addr.String(),
			RemoteASN: asn, Password: pw,
		}
		if n.Name == "" {
			n.Name = "upstream"
		}
		if v := strings.TrimSpace(r.FormValue("multihop")); v != "" {
			if n.Multihop, err = atoi(v); err != nil || n.Multihop < 0 || n.Multihop > 255 {
				return fmt.Errorf("multihop muss zwischen 0 und 255 liegen")
			}
		}
		if v := strings.TrimSpace(r.FormValue("source")); v != "" {
			src, err := netip.ParseAddr(v)
			if err != nil || src.Is6() != v6 {
				return fmt.Errorf("quelladresse passt nicht zur adressfamilie")
			}
			n.SourceAddress = src.String()
		}
		f.Neighbors = append(f.Neighbors, n)
		return nil
	})
	s.done(w, r, "/settings", err, "Neighbor hinzugefügt")
}

func (s *Server) neighborDelete(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		f, _, err := family(st, r.PathValue("fam"))
		if err != nil {
			return err
		}
		for i, n := range f.Neighbors {
			if n.ID == r.PathValue("id") {
				f.Neighbors = append(f.Neighbors[:i], f.Neighbors[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("neighbor nicht gefunden")
	})
	s.done(w, r, "/settings", err, "Neighbor gelöscht")
}

var ifaceName = func(v string) bool {
	if v == "" || len(v) > 15 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) settingsWireGuard(w http.ResponseWriter, r *http.Request) {
	var oldIface string
	err := s.Store.Update(func(st *store.State) error {
		wg := &st.Settings.WireGuard
		oldIface = wg.Interface
		iface := strings.TrimSpace(r.FormValue("interface"))
		if !ifaceName(iface) {
			return fmt.Errorf("ungültiger interface name")
		}
		port, err := atoi(r.FormValue("listen_port"))
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("ungültiger port")
		}
		mtu, err := atoi(r.FormValue("mtu"))
		if err != nil || mtu < 1280 || mtu > 9000 {
			return fmt.Errorf("mtu muss zwischen 1280 und 9000 liegen")
		}
		t4, t6 := strings.TrimSpace(r.FormValue("tunnel_v4")), strings.TrimSpace(r.FormValue("tunnel_v6"))
		if t4 != "" {
			p, err := netip.ParsePrefix(t4)
			if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
				return fmt.Errorf("tunnelnetz ipv4 ungültig (mindestens /30)")
			}
			t4 = p.Masked().String()
		}
		if t6 != "" {
			p, err := netip.ParsePrefix(t6)
			if err != nil || !p.Addr().Is6() || p.Bits() > 126 {
				return fmt.Errorf("tunnelnetz ipv6 ungültig")
			}
			t6 = p.Masked().String()
		}
		ep := strings.TrimSpace(r.FormValue("endpoint"))
		if ep != "" && !validHost(ep) {
			return fmt.Errorf("endpoint muss eine ip oder ein hostname sein (ohne port)")
		}
		wg.Interface, wg.ListenPort, wg.MTU, wg.TunnelV4, wg.TunnelV6 = iface, port, mtu, t4, t6
		wg.Endpoint = strings.Trim(ep, "[]")
		return st.AllocateTunnelIPs()
	})
	if err == nil && oldIface != "" && oldIface != s.Store.Get().Settings.WireGuard.Interface {
		go func() {
			s.Applier.mu.Lock()
			defer s.Applier.mu.Unlock()
			m := netcfgManager(s.Runner)
			if err := m.DeleteLink(oldIface); err != nil {
				log.Printf("altes interface entfernen: %v", err)
			}
		}()
	}
	s.done(w, r, "/settings", err, "WireGuard Einstellungen gespeichert")
}

func (s *Server) settingsSystem(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		sys := &st.Settings.System
		d := strings.TrimSpace(r.FormValue("dummy_interface"))
		if !ifaceName(d) {
			return fmt.Errorf("ungültiger interface name")
		}
		sys.DummyInterface = d
		sys.ManageBird = r.FormValue("manage_bird") != ""
		for _, f := range []struct {
			dst *string
			key string
		}{{&sys.BirdConfig, "bird_config"}, {&sys.BirdBinary, "bird_binary"}, {&sys.BirdcBinary, "birdc_binary"}} {
			v, err := cleanText(f.key, r.FormValue(f.key), 256)
			if err != nil {
				return err
			}
			if v != "" {
				*f.dst = v
			}
		}
		return nil
	})
	s.done(w, r, "/settings", err, "Systemeinstellungen gespeichert")
}

func (s *Server) settingsPassword(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		if !checkPassword(st.Admin, r.FormValue("current")) {
			return fmt.Errorf("aktuelles passwort falsch")
		}
		pw := r.FormValue("new")
		if len(pw) < passwordMinLen {
			return fmt.Errorf("neues passwort muss mindestens %d zeichen haben", passwordMinLen)
		}
		if pw != r.FormValue("repeat") {
			return fmt.Errorf("passwörter stimmen nicht überein")
		}
		return SetPassword(&st.Admin, pw)
	})
	if err == nil {
		s.setSessionCookie(w, r, newSession(s.Store.Get()), int(sessionTTL.Seconds()))
	}
	s.done(w, r, "/settings", err, "Passwort geändert")
}

// ---------- Agent API ----------

func remoteHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) backendByToken(token string) (store.Backend, bool) {
	if token == "" {
		return store.Backend{}, false
	}
	for _, b := range s.Store.Get().Backends {
		if constEq(b.Token, token) {
			return b, true
		}
	}
	return store.Backend{}, false
}

func agentFile(arch string) string {
	if arch == "" {
		arch = runtime.GOARCH
	}
	return "bgp-agent-linux-" + arch
}
