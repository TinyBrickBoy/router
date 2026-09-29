package router

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestEditAndPages(t *testing.T) {
	ts, st := newUserServer(t)
	st.Update(func(s *store.State) error {
		s.Settings.IPv4.Neighbors = []store.Neighbor{{ID: "n1", Name: "up", Address: "169.254.169.254", RemoteASN: 64515, Password: "geheim"}}
		s.Prefixes = []store.Prefix{{ID: "p1", CIDR: "203.0.113.0/24", Announce: true}}
		s.Backends = []store.Backend{{ID: "b1", Name: "alt", Token: "t"}}
		s.Assignments = []store.Assignment{{ID: "a1", CIDR: "203.0.113.10/32", Target: "b1"}}
		return nil
	})
	a, csrf := loginAs(t, ts.URL, "admin", "passwort123")
	post := func(path string, v url.Values) string {
		v.Set("csrf", csrf)
		resp, err := a.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "err=") {
			u, _ := url.Parse(loc)
			t.Fatalf("%s: %s", path, u.Query().Get("err"))
		}
		return loc
	}
	post("/settings/neighbors/ipv4/n1", url.Values{"name": {"neu"}, "address": {"169.254.169.1"}, "remote_asn": {"AS64516"}, "multihop": {"2"}})
	post("/prefixes/p1/edit", url.Values{"description": {"web"}, "prepend": {"3"}, "communities": {"64515:100"}})
	post("/assignments/a1/edit", url.Values{"description": {"server"}})
	post("/backends/b1/rename", url.Values{"name": {"neu"}})

	got := st.Get()
	n := got.Settings.IPv4.Neighbors[0]
	if n.Name != "neu" || n.Address != "169.254.169.1" || n.RemoteASN != 64516 || n.Multihop != 2 || n.Password != "geheim" {
		t.Errorf("neighbor: %+v", n)
	}
	if p := got.Prefixes[0]; p.Description != "web" || p.Prepend != 3 || p.Communities != "64515:100" {
		t.Errorf("präfix: %+v", p)
	}
	if got.Assignments[0].Description != "server" || got.Backends[0].Name != "neu" {
		t.Errorf("zuweisung/backend: %+v %+v", got.Assignments[0], got.Backends[0])
	}
	post("/settings/neighbors/ipv4/n1", url.Values{"address": {"169.254.169.1"}, "remote_asn": {"64516"}, "clear_password": {"1"}})
	if st.Get().Settings.IPv4.Neighbors[0].Password != "" {
		t.Error("passwort nicht entfernt")
	}

	// Alle Seiten rendern vollständig, für Admin und Viewer
	v, _ := loginAs(t, ts.URL, "noc", "viewer123")
	for _, c := range []*http.Client{a, v} {
		for _, p := range []string{"/", "/prefixes", "/assignments", "/backends", "/settings", "/updates", "/audit"} {
			req, _ := http.NewRequest("GET", ts.URL+p, nil)
			body := readBody(t, c, req)
			if !strings.Contains(body, "</footer>") {
				t.Errorf("%s bricht ab:\n%s", p, body[max(0, len(body)-300):])
			}
		}
	}
}
