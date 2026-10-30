package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/api"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func TestFirewallNetwork(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir()}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	get := func(token string) *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/network", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	// ohne Token ist der Endpoint aus
	if resp := get(""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ohne token: %d", resp.StatusCode)
	}

	st.Update(func(s *store.State) error {
		s.Settings.FirewallToken = "fw-token"
		s.Prefixes = []store.Prefix{{ID: "p", CIDR: "203.0.113.0/24", Announce: true}}
		s.Backends = []store.Backend{{ID: "b1", Name: "home", Token: "geheim-agent"}}
		s.Assignments = []store.Assignment{
			{ID: "a1", CIDR: "203.0.113.10/32", Target: "b1"},
			{ID: "a2", CIDR: "203.0.113.20/32", Target: store.TargetLocal},
		}
		return nil
	})
	if resp := get("falsch"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("falsches token: %d", resp.StatusCode)
	}
	resp := get("fw-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var raw strings.Builder
	var n api.Network
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil {
		t.Fatal(err)
	}
	if len(n.Prefixes) != 1 || n.Prefixes[0].CIDR != "203.0.113.0/24" || !n.Prefixes[0].Announce {
		t.Errorf("präfixe: %+v", n.Prefixes)
	}
	if len(n.Assignments) != 2 || n.Assignments[0].TargetName != "WireGuard → home" || n.Assignments[1].TargetName != "Lokal (VPS)" {
		t.Errorf("zuweisungen: %+v", n.Assignments)
	}
	data, _ := json.Marshal(n)
	raw.Write(data)
	if strings.Contains(raw.String(), "geheim") {
		t.Error("antwort enthält das agent token")
	}
}
