package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router/internal/store"
)

// RPKIResult ist das Ergebnis der ROA Prüfung eines Präfixes für die eigene ASN.
type RPKIResult struct {
	Status  string // valid, invalid, invalid_asn, invalid_length, unknown, fehler
	ROAs    []string
	Checked time.Time
	Err     string
}

type rpkiCache struct {
	mu sync.RWMutex
	m  map[string]RPKIResult
}

func rpkiKey(asn uint32, cidr string) string { return fmt.Sprintf("%d|%s", asn, cidr) }

func (c *rpkiCache) get(asn uint32, cidr string) (RPKIResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.m[rpkiKey(asn, cidr)]
	return r, ok
}

// checkRPKI fragt RIPEstat (Routinator) nach dem RPKI Status von cidr mit Origin asn.
func checkRPKI(ctx context.Context, asn uint32, cidr string) RPKIResult {
	res := RPKIResult{Checked: time.Now()}
	u := "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS" + strconv.FormatUint(uint64(asn), 10) + "&prefix=" + url.QueryEscape(cidr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		res.Status, res.Err = "fehler", err.Error()
		return res
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		res.Status, res.Err = "fehler", err.Error()
		return res
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			Status string `json:"status"`
			ROAs   []struct {
				Origin    string `json:"origin"`
				Prefix    string `json:"prefix"`
				MaxLength int    `json:"max_length"`
				Validity  string `json:"validity"`
			} `json:"validating_roas"`
		} `json:"data"`
	}
	if resp.StatusCode != http.StatusOK {
		res.Status, res.Err = "fehler", fmt.Sprintf("RIPEstat HTTP %d", resp.StatusCode)
		return res
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		res.Status, res.Err = "fehler", err.Error()
		return res
	}
	res.Status = body.Data.Status
	for _, r := range body.Data.ROAs {
		res.ROAs = append(res.ROAs, fmt.Sprintf("AS%s %s max /%d (%s)", strings.TrimPrefix(r.Origin, "AS"), r.Prefix, r.MaxLength, r.Validity))
	}
	return res
}

func (s *Server) rpkiCheckAll(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Get()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make([]RPKIResult, len(st.Prefixes))
	for i, p := range st.Prefixes {
		wg.Add(1)
		go func(i int, cidr string) {
			defer wg.Done()
			results[i] = checkRPKI(ctx, st.Settings.ASN, cidr)
		}(i, p.CIDR)
	}
	wg.Wait()
	s.rpki.mu.Lock()
	invalid := 0
	for i, p := range st.Prefixes {
		s.rpki.m[rpkiKey(st.Settings.ASN, p.CIDR)] = results[i]
		if strings.HasPrefix(results[i].Status, "invalid") {
			invalid++
		}
	}
	s.rpki.mu.Unlock()
	msg := fmt.Sprintf("RPKI für %d Präfixe geprüft", len(st.Prefixes))
	if invalid > 0 {
		http.Redirect(w, r, "/prefixes?err="+url.QueryEscape(fmt.Sprintf("%s: %d davon RPKI invalid, bitte ROAs prüfen", msg, invalid)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/prefixes?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) settingsRPKI(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		host := strings.Trim(strings.TrimSpace(r.FormValue("rtr_host")), "[]")
		port := 0
		if v := strings.TrimSpace(r.FormValue("rtr_port")); v != "" {
			var err error
			if port, err = atoi(v); err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("ungültiger rtr port")
			}
		}
		if host != "" && net.ParseIP(host) == nil && strings.ContainsAny(host, " \"';{}") {
			return fmt.Errorf("ungültiger rtr host")
		}
		st.Settings.RPKI.RTRHost, st.Settings.RPKI.RTRPort = host, port
		return nil
	})
	s.done(w, r, "/settings", err, "RPKI Einstellungen gespeichert")
}
