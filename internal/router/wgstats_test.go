package router

import "testing"

func TestParseWGDump(t *testing.T) {
	out := "privkey\tpubkey\t51820\toff\n" +
		"PEER1=\t(none)\t203.0.113.5:40000\t10.200.0.2/32\t1700000000\t1024\t2048\t25\n" +
		"PEER2=\t(none)\t(none)\t10.200.0.3/32\t0\t0\t0\toff\n"
	p := parseWGDump(out)
	if len(p) != 2 {
		t.Fatalf("%d peers", len(p))
	}
	a := p["PEER1="]
	if a.Endpoint != "203.0.113.5:40000" || a.Handshake.Unix() != 1700000000 || a.RX != 1024 || a.TX != 2048 {
		t.Fatalf("falsch geparst: %+v", a)
	}
	b := p["PEER2="]
	if b.Endpoint != "" || !b.Handshake.IsZero() || b.TunnelUp() {
		t.Fatalf("peer ohne handshake: %+v", b)
	}
	if humanBytes(1536) != "1.5 KiB" || humanBytes(10) != "10 B" {
		t.Fatal(humanBytes(1536))
	}
}
