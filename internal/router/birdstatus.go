package router

import (
	"strings"
)

// birdProto ist eine Zeile aus `birdc show protocols`.
type birdProto struct {
	Name  string
	Proto string
	State string
	Info  string
}

// Up meldet bei BGP Protokollen eine aufgebaute Session.
func (p birdProto) Up() bool {
	return p.State == "up" && (p.Proto != "BGP" || strings.HasPrefix(p.Info, "Established"))
}

// parseBirdProtocols liest die Ausgabe von `birdc show protocols`.
func parseBirdProtocols(out string) []birdProto {
	var res []birdProto
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "BIRD" || f[0] == "Name" {
			continue
		}
		p := birdProto{Name: f[0], Proto: f[1], State: f[3]}
		rest := f[4:]
		// Since ist entweder "12:00:00.123" oder "2024-01-01 12:00:00"
		if len(rest) > 0 {
			skip := 1
			if strings.Count(rest[0], "-") == 2 && len(rest) > 1 && strings.Contains(rest[1], ":") {
				skip = 2
			}
			if len(rest) >= skip {
				rest = rest[skip:]
			}
		}
		p.Info = strings.Join(rest, " ")
		res = append(res, p)
	}
	return res
}

// bgpSessions liefert die BGP Protokolle von BIRD (leer, wenn BIRD nicht verwaltet wird).
func (s *Server) bgpSessions(birdc string) ([]birdProto, error) {
	out, err := s.Runner.Query(birdc, "show", "protocols")
	if err != nil {
		return nil, err
	}
	var res []birdProto
	for _, p := range parseBirdProtocols(out) {
		if p.Proto == "BGP" {
			res = append(res, p)
		}
	}
	return res, nil
}
