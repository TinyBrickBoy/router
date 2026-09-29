package router

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/tinybrickboy/router/internal/api"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/wgkey"
)

func bearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// agentSync: der Agent meldet sich, der Router antwortet mit der gewünschten Konfiguration.
func (s *Server) agentSync(w http.ResponseWriter, r *http.Request) {
	b, ok := s.backendByToken(bearer(r))
	if !ok {
		http.Error(w, "ungültiges token", http.StatusUnauthorized)
		return
	}
	var req api.SyncRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "ungültige anfrage", http.StatusBadRequest)
		return
	}
	if !wgkey.Valid(req.PublicKey) {
		http.Error(w, "ungültiger public key", http.StatusBadRequest)
		return
	}
	var err error
	if req.Hostname, err = cleanText("hostname", req.Hostname, 253); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, f := range []*string{&req.Version, &req.Arch, &req.SHA256} {
		if *f, err = cleanText("feld", *f, 128); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Arch != "" && !archName.MatchString(req.Arch) {
		req.Arch = ""
	}
	s.seenMu.Lock()
	s.seen[b.ID] = agentSeen{At: time.Now(), Addr: remoteHost(r), Version: req.Version, SHA: req.SHA256, Arch: req.Arch}
	s.seenMu.Unlock()

	wantSHA, distErr := s.distSum(agentFile(req.Arch))
	upToDate := distErr == nil && wantSHA == req.SHA256
	if b.PublicKey != req.PublicKey || b.Hostname != req.Hostname || (b.UpdateRequested && upToDate) {
		changedKey := b.PublicKey != req.PublicKey
		err := s.Store.Update(func(st *store.State) error {
			if sb := st.Backend(b.ID); sb != nil {
				sb.PublicKey, sb.Hostname = req.PublicKey, req.Hostname
				if upToDate {
					sb.UpdateRequested = false
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("backend %s speichern: %v", b.Name, err)
		}
		if changedKey {
			log.Printf("backend %s registriert (%s)", b.Name, req.Hostname)
			s.audit(AuditEntry{User: "agent:" + b.Name, IP: remoteHost(r), Action: "Backend registriert", Detail: req.Hostname + " " + req.PublicKey})
			s.Applier.Trigger()
		}
		b.UpdateRequested = b.UpdateRequested && !upToDate
	}

	st := s.Store.Get()
	wg := st.Settings.WireGuard
	cfg := api.AgentConfig{
		MTU:       wg.MTU,
		Keepalive: 25,
		Endpoint:  s.endpoint(st, r),
	}
	cfg.ServerPublicKey, _ = wgkey.Public(st.WGPrivateKey)
	for _, pair := range [][2]string{{b.TunnelV4, wg.TunnelV4}, {b.TunnelV6, wg.TunnelV6}} {
		a, err1 := netip.ParseAddr(pair[0])
		p, err2 := netip.ParsePrefix(pair[1])
		if err1 == nil && err2 == nil {
			cfg.TunnelAddrs = append(cfg.TunnelAddrs, netip.PrefixFrom(a, p.Bits()).String())
		}
	}
	for _, as := range st.Assignments {
		if as.Target == b.ID {
			cfg.Routes = append(cfg.Routes, as.CIDR)
		}
	}
	if distErr == nil && !upToDate && (b.UpdateRequested || st.Settings.Update.AutoUpdateAgents) {
		cfg.Update = &api.Update{URL: "/download/" + agentFile(req.Arch), SHA256: wantSHA}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// endpoint liefert host:port unter dem die Backends den WireGuard Port erreichen.
func (s *Server) endpoint(st store.State, r *http.Request) string {
	host := strings.TrimSpace(st.Settings.WireGuard.Endpoint)
	if host == "" {
		// Fallback: die Adresse, über die der Agent uns gerade erreicht hat
		host = r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
	}
	host = strings.Trim(host, "[]")
	if !validHost(host) {
		return ""
	}
	port := st.Settings.WireGuard.EndpointPort
	if port <= 0 {
		port = st.Settings.WireGuard.ListenPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// shq quotet einen Wert für eine Shell (in einfachen Anführungszeichen).
func shq(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

var setupTmpl = template.Must(template.New("setup").Funcs(template.FuncMap{"shq": shq}).Parse(setupScript))

func (s *Server) setupScript(w http.ResponseWriter, r *http.Request) {
	b, ok := s.backendByToken(r.PathValue("token"))
	if !ok {
		http.Error(w, "echo 'ungültiges token' >&2; exit 1", http.StatusNotFound)
		return
	}
	var buf bytes.Buffer
	base := s.baseURL(s.Store.Get(), r)
	err := setupTmpl.Execute(&buf, map[string]string{
		"Server": base,
		"Token":  b.Token,
		"Pin":    s.pinFor(base),
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

var archName = regexp.MustCompile(`^(amd64|arm64|arm)$`)

var distName = regexp.MustCompile(`^bgp-(agent|router)-linux-(amd64|arm64|arm)$`)

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !distName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(s.DistDir, name)
	if _, err := os.Stat(p); err != nil {
		http.Error(w, "binary nicht vorhanden, bitte unter Updates hochladen", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, p)
}
