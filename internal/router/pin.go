package router

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/url"
	"sync"
	"time"
)

// pinCache merkt sich pro Server URL, welcher Pin dort verwendet werden soll.
type pinCache struct {
	mu sync.Mutex
	m  map[string]pinEntry
}

type pinEntry struct {
	pin string
	at  time.Time
}

// pinFor liefert den Pin, den Setup Skript und Agents für base verwenden sollen.
// Liegt vor dem Router ein HTTPS Reverse Proxy mit gültigem CA Zertifikat
// (z.B. öffentliche URL auf Port 443, Router auf 8080), sehen die Clients dessen
// Zertifikat und nicht das selbst signierte. Dann wird nicht gepinnt, sondern
// normal gegen die CA geprüft. In allen anderen Fällen bleibt der Pin erhalten.
func (s *Server) pinFor(base string) string {
	if s.Pin == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ""
	}
	s.pins.mu.Lock()
	if e, ok := s.pins.m[base]; ok && time.Since(e.at) < 5*time.Minute {
		s.pins.mu.Unlock()
		return e.pin
	}
	s.pins.mu.Unlock()

	pin := s.Pin
	if spki, caValid, err := probeTLS(u, 5*time.Second); err == nil && spki != s.Pin && caValid {
		pin = ""
	}

	s.pins.mu.Lock()
	if s.pins.m == nil {
		s.pins.m = map[string]pinEntry{}
	}
	s.pins.m[base] = pinEntry{pin: pin, at: time.Now()}
	s.pins.mu.Unlock()
	return pin
}

// probeTLS verbindet sich mit u und liefert den Public Key Hash des Server
// Zertifikats und ob die Kette gegen die System CAs für den Hostnamen gültig ist.
func probeTLS(u *url.URL, timeout time.Duration) (spki string, caValid bool, err error) {
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // nur zum Auslesen, geprüft wird unten
	})
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", false, nil
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, verr := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return base64.StdEncoding.EncodeToString(sum[:]), verr == nil, nil
}
