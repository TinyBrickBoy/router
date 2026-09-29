package router

import (
	"net/http/httptest"
	"testing"

	"github.com/tinybrickboy/router/internal/store"
)

func TestEndpoint(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "https://proxy.example.com:8443/api/agent/sync", nil)
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"", 0, "proxy.example.com:51820"},
		{"198.51.100.1", 0, "198.51.100.1:51820"},
		{"198.51.100.1", 40000, "198.51.100.1:40000"},
		{"2001:db8::1", 40000, "[2001:db8::1]:40000"},
		{"", 40000, "proxy.example.com:40000"},
	} {
		st := store.Defaults()
		st.Settings.WireGuard.Endpoint, st.Settings.WireGuard.EndpointPort = c.host, c.port
		if got := s.endpoint(st, r); got != c.want {
			t.Errorf("endpoint(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}
