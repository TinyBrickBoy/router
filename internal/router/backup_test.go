package router

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestBackupRoundTrip(t *testing.T) {
	ts, st := newUserServer(t)
	a, csrf := loginAs(t, ts.URL, "admin", "passwort123")
	st.Update(func(s *store.State) error {
		s.Prefixes = append(s.Prefixes, store.Prefix{ID: "p1", CIDR: "203.0.113.0/24"})
		return nil
	})

	resp, err := a.PostForm(ts.URL+"/backup/download", url.Values{"csrf": {csrf}, "passphrase": {"sehr-geheime-phrase"}, "passphrase_repeat": {"sehr-geheime-phrase"}})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("download: %v %v", err, resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(data, []byte(backupMagic)) || bytes.Contains(data, []byte("203.0.113.0")) {
		t.Fatal("backup nicht verschlüsselt")
	}
	if _, err := decryptBackup(data, "falsche-phrase-123"); err == nil {
		t.Fatal("falsche passphrase akzeptiert")
	}
	bad := append([]byte{}, data...)
	bad[len(bad)-1] ^= 1
	if _, err := decryptBackup(bad, "sehr-geheime-phrase"); err == nil {
		t.Fatal("manipuliertes backup akzeptiert")
	}

	// Zustand ändern und Backup wieder einspielen
	st.Update(func(s *store.State) error { s.Prefixes = nil; s.SecretKey = "anders"; return nil })
	a, csrf = loginAs(t, ts.URL, "admin", "passwort123")
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", csrf)
	mw.WriteField("passphrase", "sehr-geheime-phrase")
	fw, _ := mw.CreateFormFile("file", "x.bak")
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err = a.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?msg=") {
		t.Fatalf("wiederherstellen fehlgeschlagen: %d %s", resp.StatusCode, loc)
	}
	got := st.Get()
	if len(got.Prefixes) != 1 || got.SecretKey == "anders" {
		t.Fatalf("zustand nicht wiederhergestellt: %+v", got.Prefixes)
	}
}
