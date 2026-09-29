package router

import (
	"context"
	"net/netip"
	"sync"

	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tinybrickboy/router/internal/store"
)

const (
	sessionCookie  = "bgpr_session"
	sessionTTL     = 12 * time.Hour
	pbkdf2Iter     = 210000
	passwordMinLen = 8
)

// SetPassword setzt ein neues Passwort.
func SetPassword(a *store.User, password string) error {
	a.Salt = store.RandomHex(16)
	a.Iterations = pbkdf2Iter
	key, err := pbkdf2.Key(sha256.New, password, []byte(a.Salt), a.Iterations, 32)
	if err != nil {
		return err
	}
	a.PasswordHash = hex.EncodeToString(key)
	if a.Username == "" {
		a.Username = "admin"
	}
	return nil
}

func checkPassword(a store.User, password string) bool {
	if a.PasswordHash == "" {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, password, []byte(a.Salt), a.Iterations, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(key)), []byte(a.PasswordHash)) == 1
}

func mac(secret string, parts ...string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

// session beschreibt den angemeldeten Benutzer.
type session struct {
	User string
	Role string
	OIDC bool
}

func (s session) Admin() bool { return s.Role == store.RoleAdmin }

// sessionKey liefert die Werte, die in die Signatur einfließen. Bei lokalen
// Benutzern beenden ein Passwortwechsel oder ein Logout alle ihre Sessions,
// bei OpenID Benutzern ein Logout alle OpenID Sessions.
func sessionKey(st store.State, kind, user, role string) (string, bool) {
	switch kind {
	case "l":
		u := st.User(user)
		if u == nil || u.PasswordHash == "" {
			return "", false
		}
		return u.PasswordHash + "|" + strconv.Itoa(u.SessionEpoch), true
	case "o":
		if !st.Settings.OIDC.Enabled || (role != store.RoleAdmin && role != store.RoleViewer) {
			return "", false
		}
		return role + "|" + strconv.Itoa(st.OIDCEpoch), true
	}
	return "", false
}

func newSession(st store.State, sess session) string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	kind, role := "l", "-"
	if sess.OIDC {
		kind, role = "o", sess.Role
	}
	user := base64.RawURLEncoding.EncodeToString([]byte(sess.User))
	key, _ := sessionKey(st, kind, sess.User, role)
	payload := strings.Join([]string{exp, kind, user, role}, ".")
	return payload + "." + mac(st.SecretKey, "session", payload, key)
}

func parseSession(st store.State, v string) (session, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 5 {
		return session{}, false
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > n {
		return session{}, false
	}
	userB, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return session{}, false
	}
	kind, user, role := parts[1], string(userB), parts[3]
	key, ok := sessionKey(st, kind, user, role)
	if !ok {
		return session{}, false
	}
	payload := strings.Join(parts[:4], ".")
	if !hmac.Equal([]byte(parts[4]), []byte(mac(st.SecretKey, "session", payload, key))) {
		return session{}, false
	}
	if kind == "l" {
		return session{User: user, Role: st.UserRole(user)}, true
	}
	return session{User: user, Role: role, OIDC: true}, true
}

type sessionCtxKey struct{}

// currentSession liefert den angemeldeten Benutzer (von requireAuth gesetzt).
func currentSession(r *http.Request) session {
	s, _ := r.Context().Value(sessionCtxKey{}).(session)
	return s
}

func csrfToken(st store.State, r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return mac(st.SecretKey, "csrf", c.Value)[:32]
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// secureCookies: auch hinter einem HTTPS Reverse Proxy (öffentliche URL https://).
func (s *Server) secureCookies(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(s.Store.Get().Settings.PublicURL, "https://")
}

// loginLimiter begrenzt fehlgeschlagene Logins pro Client IP.
type loginLimiter struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

const (
	loginMaxFails = 10
	loginWindow   = 15 * time.Minute
)

func (l *loginLimiter) recent(ip string) []time.Time {
	var keep []time.Time
	for _, t := range l.fail[ip] {
		if time.Since(t) < loginWindow {
			keep = append(keep, t)
		}
	}
	return keep
}

// Blocked meldet, ob die IP gesperrt ist.
func (l *loginLimiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail == nil {
		return false
	}
	l.fail[ip] = l.recent(ip)
	return len(l.fail[ip]) >= loginMaxFails
}

func (l *loginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail == nil {
		l.fail = map[string][]time.Time{}
	}
	if len(l.fail) > 10000 { // Speicher begrenzen
		for k := range l.fail {
			if len(l.recent(k)) == 0 {
				delete(l.fail, k)
			}
		}
	}
	l.fail[ip] = append(l.recent(ip), time.Now())
}

func (l *loginLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, ip)
}

// clientIP nutzt X-Forwarded-For nur, wenn die Anfrage von localhost kommt (Reverse Proxy).
func clientIP(r *http.Request) string {
	ip := remoteHost(r)
	if a, err := netip.ParseAddr(ip); err == nil && a.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if p, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return p.String()
			}
		}
	}
	return ip
}

// Diese Aktionen dürfen auch Viewer ausführen.
var viewerPosts = map[string]bool{"/logout": true, "/settings/password": true}

// requireAuth schützt die WebUI. POST Anfragen brauchen zusätzlich ein gültiges
// CSRF Token und (außer eigenem Passwort und Abmelden) die Rolle Admin.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := s.Store.Get()
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess, ok := parseSession(st, c.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
		if r.Method == http.MethodPost {
			limit := int64(1 << 20)
			if r.URL.Path == "/updates/upload" {
				limit = 400 << 20
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.FormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(csrfToken(st, r))) != 1 {
				http.Error(w, "ungültiges CSRF Token, bitte Seite neu laden", http.StatusForbidden)
				return
			}
			if !sess.Admin() && !viewerPosts[r.URL.Path] {
				s.auditRequest(r, "Zugriff verweigert (nur lesen)", r.URL.Path, true)
				http.Error(w, "nur lesender zugriff", http.StatusForbidden)
				return
			}
			s.auditPost(w, r, next)
			return
		}
		next(w, r)
	}
}

// requireAdmin schützt Seiten, die nur Admins sehen dürfen (z.B. Backup).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !currentSession(r).Admin() {
			http.Error(w, "nur für admins", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
