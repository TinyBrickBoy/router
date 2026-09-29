// Package version hält Build Informationen und die Prüfsumme des laufenden Binaries.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// Version wird beim Build über -ldflags "-X github.com/tinybrickboy/router/internal/version.Version=v1.2.3" gesetzt.
var Version = "dev"

var (
	selfOnce sync.Once
	selfSum  string
)

// SelfSHA256 liefert die SHA256 Prüfsumme des laufenden Binaries (beim Start berechnet).
func SelfSHA256() string {
	selfOnce.Do(func() {
		p, err := os.Executable()
		if err != nil {
			return
		}
		selfSum, _ = FileSHA256(p)
	})
	return selfSum
}

// FileSHA256 berechnet die SHA256 Prüfsumme einer Datei.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
