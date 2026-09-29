package router

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func newUserServer(t *testing.T) (*httptest.Server, *store.Store) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.Update(func(s *store.State) error {
		if err := SetPassword(&s.Admin, "passwort123"); err != nil {
			return err
		}
		v := store.User{Username: "noc", Role: store.RoleViewer}
		if err := SetPassword(&v, "viewer123"); err != nil {
			return err
		}
		s.Users = append(s.Users, v)
		return nil
	})
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir(), StateDir: t.TempDir()}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

// loginAs meldet sich an und liefert Client und CSRF Token.
func loginAs(t *testing.T, base, user, pw string) (*http.Client, string) {
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	resp, err := c.PostForm(base+"/login", url.Values{"username": {user}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest("GET", base+"/settings", nil)
	body := readBody(t, c, req)
	i := strings.Index(body, `name="csrf" value="`)
	if i < 0 {
		t.Fatalf("%s nicht angemeldet", user)
	}
	return c, body[i+19 : i+19+32]
}

func TestViewerIsReadOnly(t *testing.T) {
	ts, st := newUserServer(t)
	c, csrf := loginAs(t, ts.URL, "noc", "viewer123")

	resp, _ := c.PostForm(ts.URL+"/prefixes", url.Values{"csrf": {csrf}, "cidr": {"203.0.113.0/24"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer darf präfix anlegen: %d", resp.StatusCode)
	}
	if len(st.Get().Prefixes) != 0 {
		t.Fatal("präfix wurde trotzdem angelegt")
	}
	resp, _ = c.PostForm(ts.URL+"/settings/password", url.Values{"csrf": {csrf}, "current": {"viewer123"}, "new": {"neuespasswort"}, "repeat": {"neuespasswort"}})
	if resp.StatusCode != http.StatusSeeOther || strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Fatalf("viewer kann eigenes passwort nicht ändern: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	a, acsrf := loginAs(t, ts.URL, "admin", "passwort123")
	resp, _ = a.PostForm(ts.URL+"/prefixes", url.Values{"csrf": {acsrf}, "cidr": {"203.0.113.0/24"}})
	if resp.StatusCode != http.StatusSeeOther || len(st.Get().Prefixes) != 1 {
		t.Fatalf("admin kann kein präfix anlegen: %d", resp.StatusCode)
	}
	// Hauptbenutzer lässt sich nicht löschen
	a.PostForm(ts.URL+"/settings/users/admin/delete", url.Values{"csrf": {acsrf}})
	if st.Get().Admin.Username != "admin" {
		t.Fatal("hauptbenutzer gelöscht")
	}
	// Befördern wirkt sofort auf bestehende Sessions
	a.PostForm(ts.URL+"/settings/users/noc/role", url.Values{"csrf": {acsrf}, "role": {"admin"}})
	req, _ := http.NewRequest("GET", ts.URL+"/settings", nil)
	body := readBody(t, c, req)
	i := strings.Index(body, `name="csrf" value="`)
	csrf = body[i+19 : i+19+32]
	resp, _ = c.PostForm(ts.URL+"/prefixes/rpki", url.Values{"csrf": {csrf}})
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("rolle admin wirkt nicht")
	}
}
