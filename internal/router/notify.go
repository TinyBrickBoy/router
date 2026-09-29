package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router/internal/store"
)

// Ereignisarten für Benachrichtigungen.
const (
	eventBGP     = "bgp"
	eventBackend = "backend"
	eventRPKI    = "rpki"
	eventTest    = "test"
)

// notifyEvent wird an alle eingerichteten Kanäle geschickt.
type notifyEvent struct {
	Event   string    `json:"event"`
	Title   string    `json:"title"`
	Message string    `json:"message"`
	Problem bool      `json:"problem"` // true bei Ausfall, false bei Erholung
	Router  string    `json:"router"`
	Time    time.Time `json:"time"`
}

func (e notifyEvent) text() string {
	icon := "✅"
	if e.Problem {
		icon = "⚠️"
	}
	return fmt.Sprintf("%s [%s] %s: %s", icon, e.Router, e.Title, e.Message)
}

// notifyClient: Webhooks werden mit Zeitlimit und ohne Weiterleitungen aufgerufen.
var notifyClient = &http.Client{
	Timeout:       15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func postJSON(ctx context.Context, u string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifyClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// sendMail verschickt eine E-Mail. Port 465 nutzt direktes TLS, sonst STARTTLS
// (Pflicht, sobald ein Benutzer gesetzt ist, damit das Passwort nie im Klartext läuft).
func sendMail(n store.NotifySettings, subject, body string) error {
	port := n.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(n.SMTPHost, strconv.Itoa(port))
	tlsConf := &tls.Config{ServerName: n.SMTPHost, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	var err error
	if port == 465 {
		conn, derr := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, tlsConf)
		if derr != nil {
			return derr
		}
		c, err = smtp.NewClient(conn, n.SMTPHost)
	} else {
		conn, derr := net.DialTimeout("tcp", addr, 15*time.Second)
		if derr != nil {
			return derr
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		c, err = smtp.NewClient(conn, n.SMTPHost)
		if err == nil {
			if ok, _ := c.Extension("STARTTLS"); ok {
				err = c.StartTLS(tlsConf)
			} else if n.SMTPUser != "" {
				err = errors.New("server bietet kein STARTTLS an, passwort wird nicht im klartext gesendet")
			}
		}
	}
	if err != nil {
		if c != nil {
			c.Close()
		}
		return err
	}
	defer c.Close()
	if n.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", n.SMTPUser, n.SMTPPassword, n.SMTPHost)); err != nil {
			return err
		}
	}
	from := n.MailFrom
	if from == "" {
		from = n.SMTPUser
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	to := splitList(n.MailTo)
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + from + "\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: " + mimeHeader(subject) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func mimeHeader(v string) string {
	return "=?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

// notifyEnabled meldet, ob für die Ereignisart benachrichtigt werden soll.
func notifyEnabled(n store.NotifySettings, event string) bool {
	switch event {
	case eventBGP:
		return n.BGP
	case eventBackend:
		return n.Backends
	case eventRPKI:
		return n.RPKI
	}
	return true
}

// notify verschickt ein Ereignis an alle Kanäle und liefert die Fehler.
func (s *Server) notify(ctx context.Context, e notifyEvent) error {
	n := s.Store.Get().Settings.Notify
	if !notifyEnabled(n, e.Event) {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Router == "" {
		e.Router, _ = os.Hostname()
	}
	var errs []error
	if n.DiscordWebhook != "" {
		color := 0x2e7d32
		if e.Problem {
			color = 0xc62828
		}
		body := map[string]any{"embeds": []map[string]any{{
			"title": e.Title, "description": e.Message, "color": color,
			"footer": map[string]string{"text": e.Router}, "timestamp": e.Time.UTC().Format(time.RFC3339),
		}}}
		if err := postJSON(ctx, n.DiscordWebhook, body); err != nil {
			errs = append(errs, fmt.Errorf("discord: %w", err))
		}
	}
	if n.WebhookURL != "" {
		body := map[string]any{"event": e.Event, "title": e.Title, "message": e.Message, "problem": e.Problem,
			"router": e.Router, "time": e.Time.UTC().Format(time.RFC3339), "text": e.text()}
		if err := postJSON(ctx, n.WebhookURL, body); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	if n.SMTPHost != "" && n.MailTo != "" {
		if err := sendMail(n, e.text(), e.Message+"\n\n"+e.Router+", "+e.Time.Format("02.01.2006 15:04:05")); err != nil {
			errs = append(errs, fmt.Errorf("e-mail: %w", err))
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		log.Printf("benachrichtigung %q: %v", e.Title, err)
	}
	return err
}

func (s *Server) notifyAsync(e notifyEvent) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = s.notify(ctx, e)
	}()
}

// monitor vergleicht regelmäßig BGP Sessions, Backends und RPKI mit dem
// vorherigen Zustand und benachrichtigt bei Änderungen.
type monitor struct {
	mu        sync.Mutex
	bgp       map[string]bool
	backends  map[string]bool
	rpki      map[string]string
	lastRPKI  time.Time
	bgpDownAt map[string]time.Time
}

// bgpGrace: kurze Abbrüche (z.B. BIRD Neustart beim Anwenden) nicht melden.
const bgpGrace = 60 * time.Second

func (s *Server) monitorOnce(ctx context.Context) {
	st := s.Store.Get()
	m := &s.mon
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bgp == nil {
		m.bgp, m.backends, m.rpki, m.bgpDownAt = map[string]bool{}, map[string]bool{}, map[string]string{}, map[string]time.Time{}
	}

	if st.Settings.System.ManageBird && !s.Runner.DryRun {
		if sessions, err := s.bgpSessions(st.Settings.System.BirdcBinary); err == nil {
			for _, p := range sessions {
				up := p.Up()
				prev, known := m.bgp[p.Name]
				switch {
				case !known:
					m.bgp[p.Name] = up
				case prev && !up:
					// erst nach der Karenzzeit als ausgefallen melden
					if m.bgpDownAt[p.Name].IsZero() {
						m.bgpDownAt[p.Name] = time.Now()
					} else if time.Since(m.bgpDownAt[p.Name]) >= bgpGrace {
						m.bgp[p.Name] = false
						delete(m.bgpDownAt, p.Name)
						s.notifyAsync(notifyEvent{Event: eventBGP, Problem: true, Title: "BGP Session down",
							Message: fmt.Sprintf("%s ist nicht mehr aufgebaut (%s %s)", p.Name, p.State, p.Info)})
					}
				case !prev && up:
					m.bgp[p.Name] = true
					s.notifyAsync(notifyEvent{Event: eventBGP, Title: "BGP Session up", Message: p.Name + " ist wieder aufgebaut"})
				default:
					delete(m.bgpDownAt, p.Name)
				}
			}
		}
	}

	for _, b := range s.backendViews(st) {
		if b.PublicKey == "" {
			continue // noch nicht eingerichtet
		}
		prev, known := m.backends[b.ID]
		m.backends[b.ID] = b.Online
		switch {
		case known && prev && !b.Online:
			s.notifyAsync(notifyEvent{Event: eventBackend, Problem: true, Title: "Backend offline",
				Message: fmt.Sprintf("%s (%s) meldet sich nicht mehr, zuletzt gesehen %s", b.Name, b.Hostname, b.LastSeen.Format("02.01.2006 15:04:05"))})
		case known && !prev && b.Online:
			s.notifyAsync(notifyEvent{Event: eventBackend, Title: "Backend online", Message: fmt.Sprintf("%s (%s) ist wieder erreichbar", b.Name, b.Hostname)})
		}
	}

	if len(st.Prefixes) > 0 && time.Since(m.lastRPKI) > 6*time.Hour {
		m.lastRPKI = time.Now()
		results := s.refreshRPKI(ctx, st)
		for i, p := range st.Prefixes {
			res := results[i]
			if res.Status == "fehler" {
				continue // RIPEstat nicht erreichbar, letzten Stand behalten
			}
			prev := m.rpki[p.CIDR]
			m.rpki[p.CIDR] = res.Status
			bad := strings.HasPrefix(res.Status, "invalid")
			wasBad := strings.HasPrefix(prev, "invalid")
			switch {
			case bad && !wasBad && p.Announce:
				s.notifyAsync(notifyEvent{Event: eventRPKI, Problem: true, Title: "RPKI invalid",
					Message: fmt.Sprintf("%s ist für AS%d RPKI %s, viele Netze verwerfen die Ankündigung", p.CIDR, st.Settings.ASN, res.Status)})
			case !bad && wasBad:
				s.notifyAsync(notifyEvent{Event: eventRPKI, Title: "RPKI wieder ok", Message: fmt.Sprintf("%s ist jetzt RPKI %s", p.CIDR, res.Status)})
			}
		}
	}
}

func (s *Server) monitorLoop(stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			s.monitorOnce(ctx)
			cancel()
		}
	}
}

func validNotifyURL(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%q ist keine gültige http(s) url", v)
	}
	return nil
}

func (s *Server) settingsNotify(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Update(func(st *store.State) error {
		n := &st.Settings.Notify
		for _, f := range []struct {
			dst       *string
			key       string
			keepEmpty bool // leer lassen = unverändert (Geheimnisse werden nicht angezeigt)
		}{{&n.DiscordWebhook, "discord_webhook", true}, {&n.WebhookURL, "webhook_url", true}} {
			v := strings.TrimSpace(r.FormValue(f.key))
			if err := validNotifyURL(v); err != nil {
				return err
			}
			if v != "" || !f.keepEmpty {
				*f.dst = v
			}
			if r.FormValue("clear_"+f.key) != "" {
				*f.dst = ""
			}
		}
		host := strings.TrimSpace(r.FormValue("smtp_host"))
		if host != "" && !validHost(host) {
			return fmt.Errorf("ungültiger smtp host")
		}
		n.SMTPHost = host
		n.SMTPPort = 0
		if v := strings.TrimSpace(r.FormValue("smtp_port")); v != "" {
			p, err := atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("ungültiger smtp port")
			}
			n.SMTPPort = p
		}
		var err error
		if n.SMTPUser, err = cleanText("smtp benutzer", r.FormValue("smtp_user"), 200); err != nil {
			return err
		}
		if v := r.FormValue("smtp_password"); v != "" {
			n.SMTPPassword = v
		}
		if r.FormValue("clear_smtp_password") != "" {
			n.SMTPPassword = ""
		}
		for _, f := range []struct {
			dst *string
			key string
		}{{&n.MailFrom, "mail_from"}, {&n.MailTo, "mail_to"}} {
			v, err := cleanText(f.key, r.FormValue(f.key), 500)
			if err != nil {
				return err
			}
			for _, a := range splitList(v) {
				if _, err := mail.ParseAddress(a); err != nil {
					return fmt.Errorf("ungültige e-mail adresse %q", a)
				}
			}
			*f.dst = strings.Join(splitList(v), ", ")
		}
		if n.SMTPHost != "" && n.MailTo == "" {
			return fmt.Errorf("empfänger fehlt")
		}
		n.BGP = r.FormValue("bgp") != ""
		n.Backends = r.FormValue("backends") != ""
		n.RPKI = r.FormValue("rpki") != ""
		return nil
	})
	s.done(w, r, "/settings", err, "Benachrichtigungen gespeichert")
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	n := s.Store.Get().Settings.Notify
	if n.DiscordWebhook == "" && n.WebhookURL == "" && n.SMTPHost == "" {
		s.done(w, r, "/settings", errors.New("kein kanal eingerichtet"), "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	err := s.notify(ctx, notifyEvent{Event: eventTest, Title: "Test", Message: "Testnachricht vom BGP Router (angefordert von " + currentSession(r).User + ")"})
	s.done(w, r, "/settings", err, "Testnachricht verschickt")
}
