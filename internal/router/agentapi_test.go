package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tinybrickboy/router/internal/api"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/wgkey"
)

func TestAgentSyncPublicKey(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.Update(func(s *store.State) error {
		s.Backends = []store.Backend{{ID: "a", Name: "a", Token: "token-a"}, {ID: "b", Name: "b", Token: "token-b"}}
		return nil
	})
	r := &sysexec.Runner{DryRun: true}
	s := &Server{Store: st, Applier: NewApplier(st, r, t.TempDir()), Runner: r, DistDir: t.TempDir()}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	sync := func(token, key string) int {
		body, _ := json.Marshal(api.SyncRequest{PublicKey: key, Hostname: "host"})
		req, _ := http.NewRequest("POST", ts.URL+"/api/agent/sync", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	_, keyA, _ := wgkey.Generate()
	_, keyB, _ := wgkey.Generate()
	if code := sync("token-a", keyA); code != http.StatusOK {
		t.Fatalf("registrierung: %d", code)
	}
	// Zeilenumbrüche würden in die WireGuard Konfiguration des Routers durchschlagen
	if code := sync("token-b", keyB[:22]+"\n"+keyB[22:]); code != http.StatusBadRequest {
		t.Errorf("key mit zeilenumbruch: %d", code)
	}
	if code := sync("token-b", keyA); code != http.StatusConflict {
		t.Errorf("fremder key: %d", code)
	}
	if code := sync("token-b", keyB); code != http.StatusOK {
		t.Fatalf("eigener key: %d", code)
	}
	got := st.Get()
	if got.Backend("a").PublicKey != keyA || got.Backend("b").PublicKey != keyB {
		t.Fatalf("keys falsch gespeichert: %q %q", got.Backend("a").PublicKey, got.Backend("b").PublicKey)
	}
}
