package router

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func TestSetupCommandHiddenWhileOnline(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef"
	st.Update(func(s *store.State) error {
		s.Backends = append(s.Backends, store.Backend{ID: "b1", Name: "home", Token: token})
		return nil
	})
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir()}
	s.Handler()

	page := func() string {
		rec := httptest.NewRecorder()
		s.backendsPage(rec, httptest.NewRequest("GET", "/backends", nil))
		return rec.Body.String()
	}
	if !strings.Contains(page(), token) {
		t.Fatal("setup kommando fehlt bei offline backend")
	}
	s.seenMu.Lock()
	s.seen["b1"] = agentSeen{At: time.Now()}
	s.seenMu.Unlock()
	if strings.Contains(page(), token) {
		t.Fatal("token wird trotz online agent ausgeliefert")
	}
}
