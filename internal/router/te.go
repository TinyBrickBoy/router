package router

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/tinybrickboy/router/internal/store"
)

const maxPrepend = 10

// community ist eine Standard (a:b) oder Large (a:b:c) BGP Community.
type community struct {
	Parts []uint32
}

func (c community) Large() bool { return len(c.Parts) == 3 }

func (c community) String() string {
	s := make([]string, len(c.Parts))
	for i, p := range c.Parts {
		s[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(s, ":")
}

// parseCommunities akzeptiert Communities getrennt durch Komma oder Leerzeichen.
func parseCommunities(v string) ([]community, error) {
	var out []community
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		parts := strings.Split(f, ":")
		if len(parts) != 2 && len(parts) != 3 {
			return nil, fmt.Errorf("community %q: erwartet a:b oder a:b:c", f)
		}
		c := community{}
		for _, p := range parts {
			n, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("community %q: %q ist keine zahl", f, p)
			}
			if len(parts) == 2 && n > 65535 {
				return nil, fmt.Errorf("community %q: werte bis 65535, für größere ASNs a:b:c (large community) verwenden", f)
			}
			c.Parts = append(c.Parts, uint32(n))
		}
		if !seen[c.String()] {
			seen[c.String()] = true
			out = append(out, c)
		}
	}
	return out, nil
}

func formatCommunities(cs []community) string {
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] = c.String()
	}
	return strings.Join(s, ", ")
}

// parseTE übernimmt Prepend und Communities aus dem Formular in das Präfix.
func parseTE(r *http.Request, p *store.Prefix, asn uint32) error {
	p.Prepend = 0
	if v := strings.TrimSpace(r.FormValue("prepend")); v != "" {
		n, err := atoi(v)
		if err != nil || n < 0 || n > maxPrepend {
			return fmt.Errorf("prepend muss zwischen 0 und %d liegen", maxPrepend)
		}
		p.Prepend = n
	}
	cs, err := parseCommunities(r.FormValue("communities"))
	if err != nil {
		return err
	}
	p.Communities = formatCommunities(cs)
	return nil
}
