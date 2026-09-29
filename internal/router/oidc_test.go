package router

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

type fakeIdP struct {
	srv       *httptest.Server
	nonce     string
	challenge string
	claims    map[string]any
	t         *testing.T
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "router" || pass != "s3cret" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.FormValue("code") != "good-code" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "router", "sub": "u-1", "exp": time.Now().Add(time.Minute).Unix(), "nonce": f.nonce}
		for k, v := range f.claims {
			claims[k] = v
		}
		payload, _ := json.Marshal(claims)
		tok := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
		json.NewEncoder(w).Encode(map[string]string{"id_token": tok, "token_type": "Bearer"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newTestServer(t *testing.T, oidc store.OIDCSettings) *httptest.Server {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.Update(func(s *store.State) error {
		s.Settings.OIDC = oidc
		return SetPassword(&s.Admin, "passwort123")
	})
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir()}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// login führt den Flow aus und liefert die Antwort des Callbacks.
func (f *fakeIdP) login(t *testing.T, base string, code string, tamperNonce bool) (*http.Response, *http.Client) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(base + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), f.srv.URL+"/authorize") || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != base+"/auth/callback" {
		t.Fatalf("unerwartete weiterleitung: %s", loc)
	}
	f.nonce, f.challenge = q.Get("nonce"), q.Get("code_challenge")
	if tamperNonce {
		f.nonce = "falsch"
	}
	resp, err = c.Get(base + "/auth/callback?code=" + code + "&state=" + q.Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	return resp, c
}

func TestOIDCLogin(t *testing.T) {
	f := newFakeIdP(t)
	cfg := store.OIDCSettings{Enabled: true, Issuer: f.srv.URL, ClientID: "router", ClientSecret: "s3cret", AllowedUsers: "admin@example.com", DisablePassword: true}
	ts := newTestServer(t, cfg)

	// erlaubter Benutzer
	f.claims = map[string]any{"email": "Admin@example.com", "email_verified": true}
	resp, c := f.login(t, ts.URL, "good-code", false)
	if resp.StatusCode != 200 {
		t.Fatalf("callback status %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	r2, _ := c.Get(ts.URL + "/prefixes")
	if r2.StatusCode != 200 {
		t.Fatalf("nach login kein zugriff: %d", r2.StatusCode)
	}

	cases := []struct {
		name   string
		claims map[string]any
		code   string
		nonce  bool
		want   string
	}{
		{"nicht freigeschaltet", map[string]any{"email": "boese@example.com"}, "good-code", false, "nicht+freigeschaltet"},
		{"email nicht verifiziert", map[string]any{"email": "admin@example.com", "email_verified": false}, "good-code", false, "nicht+freigeschaltet"},
		{"falsche nonce", map[string]any{"email": "admin@example.com"}, "good-code", true, "ID+Token+ung"},
		{"falscher code", map[string]any{"email": "admin@example.com"}, "bad-code", false, "Token+Austausch"},
		{"falsche aud", map[string]any{"email": "admin@example.com", "aud": "anderer"}, "good-code", false, "ID+Token+ung"},
		{"abgelaufen", map[string]any{"email": "admin@example.com", "exp": time.Now().Add(-time.Hour).Unix()}, "good-code", false, "ID+Token+ung"},
	}
	for _, tc := range cases {
		f.claims = tc.claims
		resp, _ := f.login(t, ts.URL, tc.code, tc.nonce)
		if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), tc.want) {
			t.Errorf("%s: status %d location %s", tc.name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// Gruppenfreigabe
	f.claims = map[string]any{"preferred_username": "max", "groups": []string{"/network-admins"}}
	cfg.AllowedGroups = "network-admins"
	ts2 := newTestServer(t, cfg)
	if resp, _ := f.login(t, ts2.URL, "good-code", false); resp.StatusCode != 200 {
		t.Errorf("gruppenlogin: status %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Passwort Login ist deaktiviert
	pr, _ := http.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"passwort123"}})
	if pr.StatusCode != http.StatusForbidden {
		t.Errorf("passwort login trotz deaktivierung möglich: %d", pr.StatusCode)
	}
}
