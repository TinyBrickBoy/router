package router

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/version"
)

// Backup Datei: Magic, Salt, Nonce und der mit AES-256-GCM verschlüsselte
// JSON Inhalt. Der Schlüssel wird per PBKDF2 aus der Passphrase abgeleitet.
const (
	backupMagic      = "BGPRBAK1"
	backupIter       = 600000
	backupMinPass    = 12
	backupMaxSize    = 8 << 20
	backupSaltLen    = 16
	backupNonceLen   = 12
	backupHeaderSize = len(backupMagic) + backupSaltLen + backupNonceLen
)

// backupData ist der Inhalt eines Backups. Das TLS Zertifikat gehört dazu,
// damit die Agents nach einem Umzug weiterhin den gepinnten Key vorfinden.
type backupData struct {
	Version string      `json:"version"`
	Created time.Time   `json:"created"`
	State   store.State `json:"state"`
	TLSCert string      `json:"tls_cert,omitempty"`
	TLSKey  string      `json:"tls_key,omitempty"`
}

func backupKey(pass string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, backupIter, 32)
}

func encryptBackup(d backupData, pass string) ([]byte, error) {
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, backupSaltLen)
	nonce := make([]byte, backupNonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := backupKey(pass, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := append([]byte(backupMagic), salt...)
	out = append(out, nonce...)
	// Magic, Salt und Nonce sind als zusätzliche Daten mit authentifiziert
	return gcm.Seal(out, nonce, plain, out), nil
}

func decryptBackup(data []byte, pass string) (backupData, error) {
	var d backupData
	if len(data) < backupHeaderSize || string(data[:len(backupMagic)]) != backupMagic {
		return d, errors.New("keine backup datei des bgp-routers")
	}
	header := data[:backupHeaderSize]
	salt := header[len(backupMagic) : len(backupMagic)+backupSaltLen]
	nonce := header[len(backupMagic)+backupSaltLen:]
	key, err := backupKey(pass, salt)
	if err != nil {
		return d, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return d, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return d, err
	}
	plain, err := gcm.Open(nil, nonce, data[backupHeaderSize:], header)
	if err != nil {
		return d, errors.New("passphrase falsch oder datei beschädigt")
	}
	if err := json.Unmarshal(plain, &d); err != nil {
		return d, fmt.Errorf("backup inhalt: %w", err)
	}
	if d.State.SecretKey == "" || d.State.Admin.PasswordHash == "" {
		return d, errors.New("backup ist unvollständig")
	}
	return d, nil
}

func (s *Server) tlsPaths() (string, string) {
	dir := filepath.Join(s.StateDir, "tls")
	return filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
}

func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	pass := r.FormValue("passphrase")
	if len(pass) < backupMinPass {
		s.done(w, r, "/settings", fmt.Errorf("passphrase muss mindestens %d zeichen haben", backupMinPass), "")
		return
	}
	if pass != r.FormValue("passphrase_repeat") {
		s.done(w, r, "/settings", errors.New("passphrasen stimmen nicht überein"), "")
		return
	}
	d := backupData{Version: version.Version, Created: time.Now().UTC(), State: s.Store.Get()}
	if s.StateDir != "" && s.Pin != "" {
		certPath, keyPath := s.tlsPaths()
		if c, err := os.ReadFile(certPath); err == nil {
			if k, err := os.ReadFile(keyPath); err == nil {
				d.TLSCert, d.TLSKey = string(c), string(k)
			}
		}
	}
	data, err := encryptBackup(d, pass)
	if err != nil {
		s.done(w, r, "/settings", err, "")
		return
	}
	name := "bgp-router-backup-" + time.Now().Format("20060102-150405") + ".bak"
	s.auditRequest(r, "Backup heruntergeladen", name, false)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) backupRestore(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) { s.done(w, r, "/settings", err, "") }
	f, _, err := r.FormFile("file")
	if err != nil {
		fail(errors.New("keine datei ausgewählt"))
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, backupMaxSize+1))
	if err != nil {
		fail(err)
		return
	}
	if len(data) > backupMaxSize {
		fail(errors.New("datei ist zu groß"))
		return
	}
	d, err := decryptBackup(data, r.FormValue("passphrase"))
	if err != nil {
		fail(err)
		return
	}
	if err := d.State.AllocateTunnelIPs(); err != nil {
		fail(err)
		return
	}
	certChanged := false
	if d.TLSCert != "" && d.TLSKey != "" && s.StateDir != "" && s.Pin != "" {
		certPath, keyPath := s.tlsPaths()
		if cur, _ := os.ReadFile(certPath); !bytes.Equal(cur, []byte(d.TLSCert)) {
			if err := sysexec.WriteFileAtomic(keyPath, []byte(d.TLSKey), 0o600); err != nil {
				fail(err)
				return
			}
			if err := sysexec.WriteFileAtomic(certPath, []byte(d.TLSCert), 0o644); err != nil {
				fail(err)
				return
			}
			certChanged = true
		}
	}
	if err := s.Store.Update(func(st *store.State) error { *st = d.State; return nil }); err != nil {
		fail(err)
		return
	}
	log.Printf("backup vom %s wiederhergestellt", d.Created.Format(time.RFC3339))
	s.Applier.Trigger()
	msg := "Backup vom " + d.Created.Local().Format("02.01.2006 15:04") + " wiederhergestellt, bitte mit den Zugangsdaten aus dem Backup anmelden."
	if certChanged {
		msg += " Das TLS Zertifikat aus dem Backup wird nach dem Neustart aktiv."
		s.restartLater()
	}
	// Der geheime Schlüssel kommt aus dem Backup: die aktuelle Session ist damit ungültig
	s.redirectFlash(w, r, "/login", "msg", msg)
}
