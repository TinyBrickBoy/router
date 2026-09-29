package store

import "testing"

func TestAllocateTunnelIPs(t *testing.T) {
	st := Defaults()
	st.Settings.WireGuard.TunnelV4 = "10.0.0.0/30"
	st.Backends = []Backend{{ID: "a"}, {ID: "b", TunnelV4: "10.0.0.2"}}
	// /30: .0 Netz, .1 Router, .2 vergeben, .3 Broadcast -> voll
	if err := st.AllocateTunnelIPs(); err == nil {
		t.Fatal("volles netz muss fehler liefern")
	}
	st.Settings.WireGuard.TunnelV4 = "10.0.0.0/24"
	if err := st.AllocateTunnelIPs(); err != nil {
		t.Fatal(err)
	}
	if st.Backends[1].TunnelV4 != "10.0.0.2" || st.Backends[0].TunnelV4 != "10.0.0.3" {
		t.Errorf("unerwartete vergabe: %+v", st.Backends)
	}
	if st.Backends[0].TunnelV6 != "fd00:200::2" {
		t.Errorf("v6: %q", st.Backends[0].TunnelV6)
	}
	// Netzwechsel vergibt neu
	st.Settings.WireGuard.TunnelV4 = "10.9.0.0/24"
	_ = st.AllocateTunnelIPs()
	if st.Backends[0].TunnelV4 != "10.9.0.2" {
		t.Errorf("nach wechsel: %+v", st.Backends)
	}
	got := st.RouterTunnelAddrs()
	if len(got) != 2 || got[0].String() != "10.9.0.1/24" || got[1].String() != "fd00:200::1/64" {
		t.Errorf("router adressen: %v", got)
	}
}
