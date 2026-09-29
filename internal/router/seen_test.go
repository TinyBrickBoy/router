package router

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
)

func TestSeenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &sysexec.Runner{DryRun: true}
	mk := func() *Server {
		s := &Server{Store: st, Applier: NewApplier(st, r, dir), Runner: r, DistDir: dir, StateDir: dir}
		s.Handler()
		return s
	}
	a := mk()
	at := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	a.seen["b1"] = agentSeen{At: at, Addr: "192.0.2.1", Version: "v1"}
	a.SaveSeen()

	b := mk()
	got, ok := b.seen["b1"]
	if !ok || !got.At.Equal(at) || got.Addr != "192.0.2.1" {
		t.Fatalf("online status nicht geladen: %+v", got)
	}
}
