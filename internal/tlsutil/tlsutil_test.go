package tlsutil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPinning(t *testing.T) {
	dir := t.TempDir()
	cert, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := SPKIPin(cert)
	pin2, _ := SPKIPin(again)
	if pin == "" || pin != pin2 {
		t.Fatal("zertifikat wird nicht wiederverwendet")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	if _, err := Client(pin, 5*time.Second).Get(srv.URL); err != nil {
		t.Fatalf("richtiger pin abgelehnt: %v", err)
	}
	other, _ := EnsureSelfSigned(t.TempDir())
	wrong, _ := SPKIPin(other)
	if _, err := Client(wrong, 5*time.Second).Get(srv.URL); err == nil {
		t.Fatal("falscher pin akzeptiert")
	}
	if _, err := Client("", 5*time.Second).Get(srv.URL); err == nil {
		t.Fatal("selbst signiertes zertifikat ohne pin akzeptiert")
	}
}
