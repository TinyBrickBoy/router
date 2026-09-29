package router

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// auditMaxSize: danach wird audit.log nach audit.log.1 rotiert.
const auditMaxSize = 5 << 20

// AuditEntry ist ein Eintrag im Audit Log.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	Failed bool      `json:"failed,omitempty"`
}

type auditLog struct {
	mu sync.Mutex
}

func (s *Server) auditPath() string {
	if s.StateDir == "" {
		return ""
	}
	return filepath.Join(s.StateDir, "audit.log")
}

// audit schreibt einen Eintrag (JSON pro Zeile).
func (s *Server) audit(e AuditEntry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	p := s.auditPath()
	if p == "" {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.auditLog.mu.Lock()
	defer s.auditLog.mu.Unlock()
	if fi, err := os.Stat(p); err == nil && fi.Size() > auditMaxSize {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit log: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// auditRequest protokolliert eine Aktion eines angemeldeten Benutzers.
func (s *Server) auditRequest(r *http.Request, action, detail string, failed bool) {
	s.audit(AuditEntry{User: currentSession(r).User, IP: clientIP(r), Action: action, Detail: detail, Failed: failed})
}

// readAudit liefert die letzten n Einträge, neueste zuerst.
func (s *Server) readAudit(n int) []AuditEntry {
	p := s.auditPath()
	if p == "" {
		return nil
	}
	s.auditLog.mu.Lock()
	defer s.auditLog.mu.Unlock()
	var all []AuditEntry
	for _, f := range []string{p + ".1", p} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var e AuditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				all = append(all, e)
			}
		}
		fh.Close()
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}

// Formularfelder mit Geheimnissen landen nie im Audit Log.
func secretField(k string) bool {
	k = strings.ToLower(k)
	switch k {
	case "csrf", "current", "new", "repeat":
		return true
	}
	for _, s := range []string{"pass", "secret", "token", "key", "webhook"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// formSummary fasst die gesendeten Formularwerte ohne Geheimnisse zusammen.
func formSummary(form url.Values) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if !secretField(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := strings.Join(form[k], ",")
		if len(v) > 100 {
			v = v[:100] + "…"
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

// auditWriter merkt sich die Weiterleitung, um Erfolg oder Fehler einer Aktion zu erkennen.
type auditWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

// auditPost protokolliert jede Änderung über die WebUI.
func (s *Server) auditPost(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	aw := &auditWriter{ResponseWriter: w}
	next(aw, r)
	if r.URL.Path == "/logout" {
		return // wird im Handler protokolliert
	}
	action, failed := r.Method+" "+r.URL.Path, false
	if loc, err := url.Parse(aw.Header().Get("Location")); err == nil {
		q := loc.Query()
		switch {
		case q.Get("err") != "":
			action, failed = q.Get("err"), true
		case q.Get("msg") != "":
			action = q.Get("msg")
		}
	}
	if aw.status >= 400 {
		failed = true
	}
	detail := r.URL.Path
	if f := formSummary(r.PostForm); f != "" {
		detail += " " + f
	}
	s.auditRequest(r, action, detail, failed)
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(r, "Protokoll", "audit")
	p.Audit = s.readAudit(500)
	s.render(w, "audit", p)
}
