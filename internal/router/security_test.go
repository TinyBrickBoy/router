package router

import (
	"fmt"
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
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Cache-Control") != "no-store" {
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

func TestLoginLimiterIPv6Prefix(t *testing.T) {
	var l loginLimiter
	for i := 1; i <= loginMaxFails; i++ {
		l.Fail(fmt.Sprintf("2001:db8:1:2::%x", i)) // jede Anfrage von einer anderen Adresse im selben /64
	}
	if !l.Blocked("2001:db8:1:2:ffff::1") {
		t.Error("rotation innerhalb eines /64 umgeht die sperre")
	}
	if l.Blocked("2001:db8:1:3::1") || l.Blocked("198.51.100.1") {
		t.Error("andere netze gesperrt")
	}
	for i := 1; i <= loginMaxFails; i++ {
		l.Fail(fmt.Sprintf("198.51.100.%d", i))
	}
	if l.Blocked("198.51.100.200") {
		t.Error("ipv4 adressen werden zusammengefasst")
	}
}

func TestFlashMessagesSigned(t *testing.T) {
	ts := newTestServer(t, store.OIDCSettings{})
	c := noRedirect(nil)
	// präparierter Link: der Text darf nicht als Meldung des Routers erscheinen
	req, _ := http.NewRequest("GET", ts.URL+"/login?err=Bitte+Passwort+an+boese%40example.com+senden", nil)
	if body := readBody(t, c, req); strings.Contains(body, "boese@example.com") {
		t.Fatal("unsignierte meldung wird angezeigt")
	}
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"falsch"}})
	loc := resp.Header.Get("Location")
	req, _ = http.NewRequest("GET", ts.URL+loc, nil)
	if body := readBody(t, c, req); !strings.Contains(body, "Benutzername oder Passwort falsch") {
		t.Fatalf("signierte meldung fehlt (%s)", loc)
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	q.Set("err", "Bitte Passwort an boese@example.com senden")
	req, _ = http.NewRequest("GET", ts.URL+"/login?"+q.Encode(), nil)
	if body := readBody(t, c, req); strings.Contains(body, "boese@example.com") {
		t.Fatal("signatur passt zu verändertem text")
	}
}

func TestViewerSeesNoBGPPassword(t *testing.T) {
	ts, st := newUserServer(t)
	st.Update(func(s *store.State) error {
		s.Settings.RouterID = "198.51.100.1"
		s.Settings.IPv4.Neighbors = []store.Neighbor{{ID: "n1", Name: "up", Address: "169.254.169.254", RemoteASN: 64515, Password: "bgp-geheimnis"}}
		return nil
	})
	c, csrf := loginAs(t, ts.URL, "admin", "passwort123")
	c.PostForm(ts.URL+"/apply", url.Values{"csrf": {csrf}})
	for _, u := range [][2]string{{"noc", "viewer123"}, {"admin", "passwort123"}} {
		c, _ := loginAs(t, ts.URL, u[0], u[1])
		req, _ := http.NewRequest("GET", ts.URL+"/", nil)
		body := readBody(t, c, req)
		if !strings.Contains(body, "protocol bgp") {
			t.Fatalf("%s: bird konfiguration fehlt auf der übersicht", u[0])
		}
		if strings.Contains(body, "bgp-geheimnis") {
			t.Errorf("%s sieht das bgp passwort", u[0])
		}
	}
}

func TestDummyUser(t *testing.T) {
	// unbekannte Benutzernamen kosten dieselbe PBKDF2 Rechenzeit wie bekannte
	if u := dummyUser(); u.Iterations != pbkdf2Iter || u.PasswordHash == "" || checkPassword(u, "") {
		t.Fatalf("dummy benutzer ungeeignet: %+v", u)
	}
}
