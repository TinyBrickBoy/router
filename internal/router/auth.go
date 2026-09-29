package router

import (
	"net/netip"
	"sync"

	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
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

// SetPassword setzt ein neues Admin Passwort.
func SetPassword(a *store.Admin, password string) error {
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

func checkPassword(a store.Admin, password string) bool {
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

// Passwort-Hash und SessionEpoch fließen in die Signatur ein: ein Passwortwechsel
// oder ein Logout beendet alle Sessions.
func newSession(st store.State) string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return exp + "." + mac(st.SecretKey, "session", exp, st.Admin.PasswordHash, strconv.Itoa(st.Admin.SessionEpoch))
}

func validSession(st store.State, v string) bool {
	exp, sig, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > n {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(mac(st.SecretKey, "session", exp, st.Admin.PasswordHash, strconv.Itoa(st.Admin.SessionEpoch))))
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

// requireAuth schützt die WebUI. POST Anfragen brauchen zusätzlich ein gültiges CSRF Token.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := s.Store.Get()
		c, err := r.Cookie(sessionCookie)
		if err != nil || !validSession(st, c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
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
		}
		next(w, r)
	}
}
