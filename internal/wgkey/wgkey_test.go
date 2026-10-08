package wgkey

import "testing"

func TestValid(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(pub) || !Valid(priv) {
		t.Fatal("erzeugter schlüssel abgelehnt")
	}
	if got, _ := Public(priv); got != pub {
		t.Fatal("public key passt nicht")
	}
	for name, v := range map[string]string{
		"zeilenumbruch mitten drin": pub[:22] + "\n" + pub[22:],
		"neue config zeile":         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAllowedIPs=",
		"zeilenumbruch am ende":     pub + "\n",
		"leerzeichen":               " " + pub,
		"zu kurz":                   pub[:43],
		"leer":                      "",
		"nicht kanonisch":           pub[:42] + "B=",
	} {
		if Valid(v) {
			t.Errorf("%s: %q akzeptiert", name, v)
		}
	}
}
