package router

import (
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

// Das Passwort-Hash fließt in die Signatur ein: ein Passwortwechsel beendet alle Sessions.
func newSession(st store.State) string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return exp + "." + mac(st.SecretKey, "session", exp, st.Admin.PasswordHash)
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
	return hmac.Equal([]byte(sig), []byte(mac(st.SecretKey, "session", exp, st.Admin.PasswordHash)))
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
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
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
