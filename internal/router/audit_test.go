package router

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuditLog(t *testing.T) {
	ts, _ := newUserServer(t)
	a, csrf := loginAs(t, ts.URL, "admin", "passwort123")
	a.PostForm(ts.URL+"/prefixes", url.Values{"csrf": {csrf}, "cidr": {"203.0.113.0/24"}, "description": {"test"}})
	a.PostForm(ts.URL+"/settings/users", url.Values{"csrf": {csrf}, "username": {"max"}, "password": {"geheim-passwort-42"}, "role": {"viewer"}})
	v, vcsrf := loginAs(t, ts.URL, "noc", "viewer123")
	v.PostForm(ts.URL+"/prefixes", url.Values{"csrf": {vcsrf}, "cidr": {"198.51.100.0/24"}})

	req, _ := http.NewRequest("GET", ts.URL+"/audit", nil)
	body := readBody(t, a, req)
	for _, want := range []string{"Präfix 203.0.113.0/24 hinzugefügt", "description=test", "Benutzer max angelegt", "Zugriff verweigert", "Anmeldung"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q fehlt im protokoll", want)
		}
	}
	if strings.Contains(body, "geheim-passwort-42") {
		t.Error("passwort im protokoll")
	}
}
