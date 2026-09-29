// Package wgkey erzeugt WireGuard Schlüssel (Curve25519) ohne externe Tools.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Generate erzeugt ein neues Schlüsselpaar (base64, wie `wg genkey` / `wg pubkey`).
func Generate() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Public berechnet den öffentlichen Schlüssel zu einem privaten Schlüssel.
func Public(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil {
		return "", fmt.Errorf("ungültiger privater Schlüssel: %w", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Valid prüft ob s ein gültiger base64 Schlüssel mit 32 Byte ist.
func Valid(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return err == nil && len(raw) == 32
}
