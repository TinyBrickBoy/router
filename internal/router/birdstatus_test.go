package router

import "testing"

func TestParseBirdProtocols(t *testing.T) {
	out := `BIRD 2.0.12 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     2024-01-01 12:00:00  
announce4  Static     master4    up     12:00:00.123  
bgp4_1_upstream BGP        ---        up     2024-01-01 12:00:01  Established   
bgp6_1_upstream BGP        ---        start  12:00:00.123  Active        Socket: Connection refused
`
	p := parseBirdProtocols(out)
	if len(p) != 4 {
		t.Fatalf("%d protokolle: %+v", len(p), p)
	}
	if !p[2].Up() || p[2].Info != "Established" {
		t.Fatalf("session 1: %+v", p[2])
	}
	if p[3].Up() || p[3].Info != "Active Socket: Connection refused" {
		t.Fatalf("session 2: %+v", p[3])
	}
	if !p[1].Up() {
		t.Fatal("static nicht up")
	}
}
