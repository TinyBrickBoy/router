package router

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router/internal/store"
)

// OpenID Connect Authorization Code Flow mit PKCE.
//
// Das ID Token wird direkt per TLS vom Token Endpoint des Providers geholt
// (vertraulicher Client). Laut OIDC Core 3.1.3.7 ersetzt die TLS Prüfung dann
// die Signaturprüfung; iss, aud, azp, exp und nonce werden trotzdem geprüft.

const oidcCookie = "bgpr_oidc"

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type oidcClient struct {
	mu      sync.Mutex
	issuer  string
	disc    *oidcDiscovery
	fetched time.Time
	http    *http.Client
}

func (c *oidcClient) discover(ctx context.Context, issuer string) (*oidcDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disc != nil && c.issuer == issuer && time.Since(c.fetched) < time.Hour {
		return c.disc, nil
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("discovery: issuer %q passt nicht zu %q", d.Issuer, issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, errors.New("discovery: endpunkte fehlen")
	}
	c.issuer, c.disc, c.fetched = issuer, &d, time.Now()
	return &d, nil
}

// validIssuerURL erlaubt nur https (http nur für localhost zum Testen).
func validIssuerURL(v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return errors.New("issuer url ungültig")
	}
	if u.Scheme == "https" {
		return nil
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); u.Scheme == "http" && (h == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("issuer muss https verwenden")
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) redirectURI(st store.State, r *http.Request) string {
	return s.baseURL(st, r) + "/auth/callback"
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Get()
	o := st.Settings.OIDC
	if !o.Enabled {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	d, err := s.oidc.discover(r.Context(), o.Issuer)
	if err != nil {
		log.Printf("oidc: %v", err)
		http.Redirect(w, r, "/login?err="+url.QueryEscape("OpenID Provider nicht erreichbar: "+err.Error()), http.StatusSeeOther)
		return
	}
	state, nonce, verifier := store.RandomHex(16), store.RandomHex(16), store.RandomHex(32)
	exp := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	payload := strings.Join([]string{state, nonce, verifier, exp}, ".")
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: payload + "." + mac(st.SecretKey, "oidc", payload),
		Path: "/auth/", MaxAge: 600, HttpOnly: true, Secure: s.secureCookies(r),
		SameSite: http.SameSiteLaxMode, // muss beim Rücksprung vom Provider mitgesendet werden
	})
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {s.redirectURI(st, r)},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {b64url(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, d.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
}

type idClaims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	Azp               string          `json:"azp"`
	Exp               int64           `json:"exp"`
	Nonce             string          `json:"nonce"`
	Email             string          `json:"email"`
	EmailVerified     *bool           `json:"email_verified"`
	PreferredUsername string          `json:"preferred_username"`
	Groups            []string        `json:"groups"`
}

func (c idClaims) audiences() []string {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(c.Aud, &many)
	return many
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string, err error) {
		s.logins.Fail(clientIP(r))
		if err != nil {
			log.Printf("oidc login fehlgeschlagen: %s: %v", msg, err)
		} else {
			log.Printf("oidc login fehlgeschlagen: %s", msg)
		}
		http.Redirect(w, r, "/login?err="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if s.logins.Blocked(clientIP(r)) {
		http.Error(w, "zu viele fehlgeschlagene anmeldungen, bitte später erneut versuchen", http.StatusTooManyRequests)
		return
	}
	st := s.Store.Get()
	o := st.Settings.OIDC
	if !o.Enabled {
		fail("OpenID Login ist deaktiviert", nil)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail("Provider meldet: "+e+" "+r.URL.Query().Get("error_description"), nil)
		return
	}
	c, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteLaxMode})
	if err != nil {
		fail("Login Sitzung abgelaufen, bitte erneut versuchen", nil)
		return
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 5 || !hmac.Equal([]byte(parts[4]), []byte(mac(st.SecretKey, "oidc", strings.Join(parts[:4], ".")))) {
		fail("ungültige Login Sitzung", nil)
		return
	}
	state, nonce, verifier := parts[0], parts[1], parts[2]
	if exp, _ := strconv.ParseInt(parts[3], 10, 64); time.Now().Unix() > exp {
		fail("Login Sitzung abgelaufen, bitte erneut versuchen", nil)
		return
	}
	if !hmac.Equal([]byte(r.URL.Query().Get("state")), []byte(state)) {
		fail("ungültiger state Parameter", nil)
		return
	}
	d, err := s.oidc.discover(r.Context(), o.Issuer)
	if err != nil {
		fail("OpenID Provider nicht erreichbar", err)
		return
	}
	claims, err := s.exchangeCode(r.Context(), d, o, r.URL.Query().Get("code"), verifier, s.redirectURI(st, r))
	if err != nil {
		fail("Token Austausch fehlgeschlagen", err)
		return
	}
	if err := checkClaims(claims, o, d.Issuer, nonce); err != nil {
		fail("ID Token ungültig", err)
		return
	}
	user, role, ok := oidcAllowed(claims, o)
	if !ok {
		fail(fmt.Sprintf("Benutzer %q ist nicht freigeschaltet", user), nil)
		return
	}
	s.logins.Reset(clientIP(r))
	log.Printf("oidc login: %s (sub %s, %s) von %s", user, claims.Sub, role, clientIP(r))
	s.setSessionCookie(w, r, newSession(st, session{User: user, Role: role, OIDC: true}), int(sessionTTL.Seconds()))
	// Per HTML weiterleiten statt 303: sonst gilt die Weiterleitung als Teil der
	// Cross-Site Navigation vom Provider und der SameSite=Strict Cookie fehlt.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = redirectPage.Execute(w, "/")
}

var redirectPage = template.Must(template.New("r").Parse(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={{.}}"><title>Anmeldung…</title><a href="{{.}}">Weiter</a>`))

func (s *Server) exchangeCode(ctx context.Context, d *oidcDiscovery, o store.OIDCSettings, code, verifier, redirect string) (idClaims, error) {
	var claims idClaims
	if code == "" {
		return claims, errors.New("kein code erhalten")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {o.ClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return claims, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if o.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(o.ClientSecret))
	}
	resp, err := s.oidc.http.Do(req)
	if err != nil {
		return claims, err
	}
	defer resp.Body.Close()
	var body struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return claims, fmt.Errorf("HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || body.IDToken == "" {
		return claims, fmt.Errorf("HTTP %d: %s %s", resp.StatusCode, body.Error, body.Desc)
	}
	parts := strings.Split(body.IDToken, ".")
	if len(parts) != 3 {
		return claims, errors.New("id token hat kein jwt format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return claims, fmt.Errorf("id token: %w", err)
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, fmt.Errorf("id token: %w", err)
	}
	return claims, nil
}

func checkClaims(c idClaims, o store.OIDCSettings, issuer, nonce string) error {
	if strings.TrimRight(c.Iss, "/") != strings.TrimRight(issuer, "/") {
		return fmt.Errorf("falscher issuer %q", c.Iss)
	}
	auds := c.audiences()
	found := false
	for _, a := range auds {
		if a == o.ClientID {
			found = true
		}
	}
	if !found {
		return errors.New("token ist nicht für diesen client ausgestellt")
	}
	if len(auds) > 1 && c.Azp != o.ClientID {
		return errors.New("azp passt nicht")
	}
	if time.Now().Unix() > c.Exp+60 {
		return errors.New("token abgelaufen")
	}
	if !hmac.Equal([]byte(c.Nonce), []byte(nonce)) {
		return errors.New("nonce passt nicht")
	}
	if c.Sub == "" {
		return errors.New("sub fehlt")
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// oidcAllowed prüft Benutzer und Gruppen. Ohne Freigaben wird niemand eingelassen.
// oidcAllowed liefert Benutzername und Rolle. Admin Freigaben haben Vorrang.
func oidcAllowed(c idClaims, o store.OIDCSettings) (string, string, bool) {
	user := c.PreferredUsername
	email := ""
	if c.Email != "" && (c.EmailVerified == nil || *c.EmailVerified) {
		email = c.Email
		if user == "" {
			user = email
		}
	}
	if user == "" {
		user = c.Sub
	}
	match := func(users, groups string) bool {
		for _, a := range splitList(users) {
			if a == c.Sub || (email != "" && strings.EqualFold(a, email)) || (c.PreferredUsername != "" && a == c.PreferredUsername) {
				return true
			}
		}
		for _, g := range splitList(groups) {
			for _, cg := range c.Groups {
				if g == cg || "/"+g == cg {
					return true
				}
			}
		}
		return false
	}
	switch {
	case match(o.AllowedUsers, o.AllowedGroups):
		return user, store.RoleAdmin, true
	case match(o.ViewerUsers, o.ViewerGroups):
		return user, store.RoleViewer, true
	}
	return user, "", false
}

func (s *Server) settingsOIDC(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		o := &st.Settings.OIDC
		o.Enabled = r.FormValue("enabled") != ""
		o.Issuer = strings.TrimRight(strings.TrimSpace(r.FormValue("issuer")), "/")
		o.ClientID = strings.TrimSpace(r.FormValue("client_id"))
		if v := r.FormValue("client_secret"); v != "" {
			o.ClientSecret = v
		}
		if r.FormValue("clear_secret") != "" {
			o.ClientSecret = ""
		}
		o.AllowedUsers = strings.Join(splitList(r.FormValue("allowed_users")), ", ")
		o.AllowedGroups = strings.Join(splitList(r.FormValue("allowed_groups")), ", ")
		o.ViewerUsers = strings.Join(splitList(r.FormValue("viewer_users")), ", ")
		o.ViewerGroups = strings.Join(splitList(r.FormValue("viewer_groups")), ", ")
		o.DisablePassword = r.FormValue("disable_password") != ""
		if !o.Enabled {
			o.DisablePassword = false
			return nil
		}
		if err := validIssuerURL(o.Issuer); err != nil {
			return err
		}
		if o.ClientID == "" {
			return errors.New("client id fehlt")
		}
		if o.AllowedUsers == "" && o.AllowedGroups == "" {
			return errors.New("mindestens einen erlaubten benutzer oder eine gruppe eintragen")
		}
		return nil
	})
	s.done(w, r, "/settings", err, "OpenID Connect Einstellungen gespeichert")
}
