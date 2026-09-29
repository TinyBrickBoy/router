package router

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestMetrics(t *testing.T) {
	ts, st := newUserServer(t)
	get := func(tok string) (int, string) {
		req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get(""); code != http.StatusNotFound {
		t.Fatalf("ohne token aktiv: %d", code)
	}
	st.Update(func(s *store.State) error {
		s.Settings.MetricsToken = "abc123"
		s.Prefixes = append(s.Prefixes, store.Prefix{ID: "p1", CIDR: "203.0.113.0/24", Announce: true})
		s.Backends = append(s.Backends, store.Backend{ID: "b1", Name: `home"1`})
		return nil
	})
	if code, _ := get("falsch"); code != http.StatusUnauthorized {
		t.Fatalf("falsches token: %d", code)
	}
	code, body := get("abc123")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		"# TYPE bgp_router_info gauge",
		`bgp_router_prefix_announced{prefix="203.0.113.0/24"} 1`,
		`bgp_router_backend_online{backend="home\"1"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q fehlt:\n%s", want, body)
		}
	}
}
