package router

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tinybrickboy/router/internal/sysexec"
)

// Der Online Status der Agents liegt im Speicher und wird regelmäßig in
// seen.json gesichert, damit er einen Neustart oder ein Update übersteht.

func (s *Server) seenPath() string {
	if s.StateDir == "" {
		return ""
	}
	return filepath.Join(s.StateDir, "seen.json")
}

func (s *Server) loadSeen() {
	p := s.seenPath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	m := map[string]agentSeen{}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("%s: %v", p, err)
		return
	}
	s.seenMu.Lock()
	for id, v := range m {
		if cur, ok := s.seen[id]; !ok || cur.At.Before(v.At) {
			s.seen[id] = v
		}
	}
	s.seenMu.Unlock()
}

// SaveSeen schreibt den Online Status auf die Platte.
func (s *Server) SaveSeen() {
	p := s.seenPath()
	if p == "" {
		return
	}
	s.seenMu.RLock()
	data, err := json.Marshal(s.seen)
	s.seenMu.RUnlock()
	if err == nil {
		err = sysexec.WriteFileAtomic(p, data, 0o600)
	}
	if err != nil {
		log.Printf("online status speichern: %v", err)
	}
}

func (s *Server) seenLoop(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.SaveSeen()
		}
	}
}
