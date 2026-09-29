package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func TestNotifyBackendOffline(t *testing.T) {
	got := make(chan map[string]any, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		got <- m
	}))
	defer hook.Close()

	st, _ := store.Open(filepath.Join(t.TempDir(), "state.json"))
	st.Update(func(s *store.State) error {
		s.Settings.Notify.WebhookURL = hook.URL
		s.Backends = append(s.Backends, store.Backend{ID: "b1", Name: "home", PublicKey: "k"})
		return nil
	})
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir()}
	s.Handler()

	s.seen["b1"] = agentSeen{At: time.Now()}
	s.monitorOnce(context.Background()) // Ausgangszustand online, keine Meldung
	s.seen["b1"] = agentSeen{At: time.Now().Add(-5 * time.Minute)}
	s.monitorOnce(context.Background())

	select {
	case m := <-got:
		if m["event"] != "backend" || m["problem"] != true || m["title"] != "Backend offline" {
			t.Fatalf("unerwartete meldung: %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keine benachrichtigung")
	}
	select {
	case m := <-got:
		t.Fatalf("doppelte meldung: %v", m)
	case <-time.After(200 * time.Millisecond):
	}

	// Ereignisart abgeschaltet: keine Meldung
	st.Update(func(s *store.State) error { s.Settings.Notify.Backends = false; return nil })
	s.seen["b1"] = agentSeen{At: time.Now()}
	s.monitorOnce(context.Background())
	select {
	case m := <-got:
		t.Fatalf("meldung trotz abgeschaltet: %v", m)
	case <-time.After(200 * time.Millisecond):
	}
}
