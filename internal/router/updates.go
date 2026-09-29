package router

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/update"
	"github.com/tinybrickboy/router/internal/version"
)

type distEntry struct {
	mod  time.Time
	size int64
	sum  string
}

// distSum liefert die (gecachte) SHA256 Summe einer Datei im Dist Verzeichnis.
func (s *Server) distSum(name string) (string, error) {
	p := filepath.Join(s.DistDir, name)
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	s.distMu.Lock()
	defer s.distMu.Unlock()
	if e, ok := s.distCache[name]; ok && e.mod.Equal(fi.ModTime()) && e.size == fi.Size() {
		return e.sum, nil
	}
	sum, err := version.FileSHA256(p)
	if err != nil {
		return "", err
	}
	s.distCache[name] = distEntry{mod: fi.ModTime(), size: fi.Size(), sum: sum}
	return sum, nil
}

type distFileView struct {
	Name     string
	SHA      string
	Size     string
	Modified time.Time
}

type updatesView struct {
	SelfSHA    string
	Arch       string
	Exe        string
	HasBackup  bool
	Files      []distFileView
	Restarting bool
}

func (s *Server) updatesPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Updates", "updates")
	u := &updatesView{SelfSHA: version.SelfSHA256(), Arch: runtime.GOARCH, Exe: update.Executable(), Restarting: r.URL.Query().Get("restart") == "1"}
	if _, err := os.Stat(u.Exe + ".bak"); err == nil {
		u.HasBackup = true
	}
	entries, _ := os.ReadDir(s.DistDir)
	for _, e := range entries {
		if !distName.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		sum, _ := s.distSum(e.Name())
		u.Files = append(u.Files, distFileView{Name: e.Name(), SHA: sum, Size: fmt.Sprintf("%.1f MB", float64(fi.Size())/1e6), Modified: fi.ModTime()})
	}
	sort.Slice(u.Files, func(i, j int) bool { return u.Files[i].Name < u.Files[j].Name })
	p.Updates = u
	p.Backends = s.backendViews(p.S)
	s.render(w, "updates", p)
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		repo := strings.Trim(strings.TrimSpace(r.FormValue("github_repo")), "/")
		if repo != "" && strings.Count(repo, "/") != 1 {
			return fmt.Errorf("repository im format besitzer/name angeben")
		}
		st.Settings.Update.GitHubRepo = repo
		st.Settings.Update.AutoUpdateAgents = r.FormValue("auto_update_agents") != ""
		return nil
	})
	s.done(w, r, "/updates", err, "Update Einstellungen gespeichert")
}

// installSelf ersetzt das Router Binary durch dist/<name>, falls es sich unterscheidet.
// Liefert true, wenn ein Neustart nötig ist.
func (s *Server) installSelf() (bool, error) {
	name := "bgp-router-linux-" + runtime.GOARCH
	sum, err := s.distSum(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if sum == version.SelfSHA256() {
		return false, nil
	}
	if err := update.Install(filepath.Join(s.DistDir, name), update.Executable()); err != nil {
		return false, err
	}
	log.Printf("router binary aktualisiert (%s)", sum[:12])
	return true, nil
}

func (s *Server) restartLater() {
	go func() {
		time.Sleep(500 * time.Millisecond)
		if s.Restart == nil {
			log.Printf("neustart nicht möglich: keine restart funktion")
			return
		}
		if err := s.Restart(); err != nil {
			log.Printf("neustart fehlgeschlagen: %v", err)
		}
	}()
}

func (s *Server) finishUpdate(w http.ResponseWriter, r *http.Request, stored []string, err error) {
	if err != nil {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	restart, err := s.installSelf()
	if err != nil {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape("router update: "+err.Error()), http.StatusSeeOther)
		return
	}
	msg := "Keine neuen Dateien"
	if len(stored) > 0 {
		msg = "Aktualisiert: " + strings.Join(stored, ", ")
	}
	q := url.Values{"msg": {msg}}
	if restart {
		q.Set("msg", msg+". Router startet ohne Unterbrechung neu …")
		q.Set("restart", "1")
		s.restartLater()
	}
	http.Redirect(w, r, "/updates?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) updateUpload(w http.ResponseWriter, r *http.Request) {
	if !s.updateMu.TryLock() {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape("ein update läuft bereits"), http.StatusSeeOther)
		return
	}
	defer s.updateMu.Unlock()
	var stored []string
	err := func() error {
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		files := r.MultipartForm.File["files"]
		if len(files) == 0 {
			return fmt.Errorf("keine datei ausgewählt")
		}
		for _, fh := range files {
			name := filepath.Base(fh.Filename)
			if !distName.MatchString(name) {
				return fmt.Errorf("%s: dateiname muss bgp-router-linux-<arch> oder bgp-agent-linux-<arch> sein", name)
			}
		}
		for _, fh := range files {
			name := filepath.Base(fh.Filename)
			f, err := fh.Open()
			if err != nil {
				return err
			}
			if err := s.storeDist(name, f, ""); err != nil {
				f.Close()
				return err
			}
			f.Close()
			stored = append(stored, name)
		}
		return nil
	}()
	s.finishUpdate(w, r, stored, err)
}

// storeDist speichert ein Binary im Dist Verzeichnis. Binaries für die eigene
// Architektur werden vorher per Selbsttest geprüft.
func (s *Server) storeDist(name string, src interface{ Read([]byte) (int, error) }, wantSHA string) error {
	if err := os.MkdirAll(s.DistDir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(s.DistDir, "."+name+".upload")
	defer os.Remove(tmp)
	if _, err := update.WriteVerified(src, tmp, wantSHA); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if strings.HasSuffix(name, "-"+runtime.GOARCH) {
		if _, err := update.SelfTest(tmp); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return os.Rename(tmp, filepath.Join(s.DistDir, name))
}

func (s *Server) updateGitHub(w http.ResponseWriter, r *http.Request) {
	if !s.updateMu.TryLock() {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape("ein update läuft bereits"), http.StatusSeeOther)
		return
	}
	defer s.updateMu.Unlock()
	var stored []string
	err := func() error {
		repo := s.Store.Get().Settings.Update.GitHubRepo
		if repo == "" {
			return fmt.Errorf("kein github repository eingestellt")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		client := &http.Client{Timeout: 5 * time.Minute}
		rel, err := update.LatestRelease(ctx, client, repo)
		if err != nil {
			return err
		}
		for name, u := range rel.Assets {
			if !distName.MatchString(name) {
				continue
			}
			sum, ok := rel.Sums[name]
			if !ok {
				return fmt.Errorf("%s fehlt in SHA256SUMS", name)
			}
			if cur, err := s.distSum(name); err == nil && cur == sum {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
			}
			err = s.storeDist(name, resp.Body, sum)
			resp.Body.Close()
			if err != nil {
				return err
			}
			stored = append(stored, name)
		}
		sort.Strings(stored)
		log.Printf("github release %s geprüft, %d dateien aktualisiert", rel.Tag, len(stored))
		return nil
	}()
	s.finishUpdate(w, r, stored, err)
}

func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	bak := update.Executable() + ".bak"
	if _, err := os.Stat(bak); err != nil {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape("kein backup vorhanden"), http.StatusSeeOther)
		return
	}
	tmp := bak + ".restore"
	data, err := os.ReadFile(bak)
	if err == nil {
		err = os.WriteFile(tmp, data, 0o755)
	}
	if err == nil {
		err = update.Install(tmp, update.Executable())
		os.Remove(tmp)
	}
	if err != nil {
		http.Redirect(w, r, "/updates?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.restartLater()
	http.Redirect(w, r, "/updates?restart=1&msg="+url.QueryEscape("Vorherige Version wird gestartet …"), http.StatusSeeOther)
}

func (s *Server) updateAllAgents(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		for i := range st.Backends {
			st.Backends[i].UpdateRequested = true
		}
		return nil
	})
	s.done(w, r, "/updates", err, "Alle Agents aktualisieren sich bei der nächsten Synchronisation (max. 30s)")
}

func (s *Server) backendUpdate(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		b := st.Backend(r.PathValue("id"))
		if b == nil {
			return fmt.Errorf("backend nicht gefunden")
		}
		b.UpdateRequested = true
		return nil
	})
	back := "/backends"
	if strings.HasSuffix(r.Referer(), "/updates") {
		back = "/updates"
	}
	s.done(w, r, back, err, "Agent aktualisiert sich bei der nächsten Synchronisation")
}
