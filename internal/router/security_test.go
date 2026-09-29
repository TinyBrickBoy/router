package router

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func noRedirect(jar http.CookieJar) *http.Client {
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestLoginRateLimitAndLogout(t *testing.T) {
	ts := newTestServer(t, store.OIDCSettings{})
	c := noRedirect(nil)
	for i := 0; i < loginMaxFails; i++ {
		c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"falsch"}})
	}
	// auch das richtige Passwort wird jetzt abgelehnt
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"passwort123"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "Zu+viele") {
		t.Fatalf("keine sperre nach %d fehlversuchen: %s", loginMaxFails, loc)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	ts := newTestServer(t, store.OIDCSettings{})
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"passwort123"}})
	u, _ := url.Parse(ts.URL)
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		t.Fatal("kein session cookie")
	}
	stolen := cookies[0].Value

	resp, _ := c.Get(ts.URL + "/settings")
	if resp.StatusCode != 200 {
		t.Fatalf("nicht eingeloggt: %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security header fehlen")
	}
	// CSRF Token aus der Seite holen und abmelden
	req, _ := http.NewRequest("GET", ts.URL+"/settings", nil)
	body := readBody(t, c, req)
	i := strings.Index(body, `name="csrf" value="`)
	tok := body[i+19 : i+19+32]
	c.PostForm(ts.URL+"/logout", url.Values{"csrf": {tok}})

	// der alte (z.B. gestohlene) Cookie ist ungültig
	req, _ = http.NewRequest("GET", ts.URL+"/settings", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: stolen})
	resp, _ = noRedirect(nil).Do(req)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("session nach logout noch gültig: %d", resp.StatusCode)
	}
}

func readBody(t *testing.T, c *http.Client, req *http.Request) string {
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

func TestInputValidation(t *testing.T) {
	if _, err := cleanText("x", "a\nb", 100); err == nil {
		t.Error("zeilenumbruch akzeptiert")
	}
	for _, h := range []string{"router.example.com", "198.51.100.1", "2001:db8::1", "[2001:db8::1]"} {
		if !validHost(h) {
			t.Errorf("%s abgelehnt", h)
		}
	}
	for _, h := range []string{"a b", "x\n", "evil.com:1234", "-a.com", ""} {
		if validHost(h) {
			t.Errorf("%q akzeptiert", h)
		}
	}
}
