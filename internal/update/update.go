// Package update tauscht das laufende Binary ohne Downtime aus.
//
// Ablauf: neues Binary herunterladen/hochladen -> SHA256 prüfen -> Selbsttest
// (`<binary> version`) -> atomar über das alte Binary schieben (Backup *.bak)
// -> Prozess per execve(2) in place ersetzen. Die PID bleibt gleich, systemd
// merkt nichts, und offene Listener werden an den neuen Prozess vererbt.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var exePath string

func init() {
	if p, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		exePath = p
	}
}

// Executable liefert den Pfad des laufenden Binaries (beim Start ermittelt).
func Executable() string { return exePath }

// Download lädt url nach dest und prüft optional die SHA256 Summe.
func Download(ctx context.Context, client *http.Client, url, dest, wantSHA string, header http.Header) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return WriteVerified(resp.Body, dest, wantSHA)
}

// WriteVerified schreibt r nach dest (atomar, ausführbar) und prüft die SHA256 Summe.
func WriteVerified(r io.Reader, dest, wantSHA string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".new*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, 256<<20)); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(sum, wantSHA) {
		return "", fmt.Errorf("prüfsumme stimmt nicht: erwartet %s, erhalten %s", wantSHA, sum)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", err
	}
	return sum, nil
}

// SelfTest führt `<binary> version` aus und liefert die gemeldete Version.
func SelfTest(binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil {
		return "", fmt.Errorf("selbsttest von %s fehlgeschlagen: %w", binary, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", errors.New("selbsttest: keine versionsausgabe")
	}
	return v, nil
}

// Install ersetzt target atomar durch newBinary und legt target.bak an.
func Install(newBinary, target string) error {
	if _, err := SelfTest(newBinary); err != nil {
		return err
	}
	if data, err := os.ReadFile(target); err == nil {
		_ = os.WriteFile(target+".bak", data, 0o755)
	}
	// Immer erst neben das Ziel kopieren: rename ist nur im selben Dateisystem atomar
	// und die Quelle (z.B. im Dist Verzeichnis) soll erhalten bleiben.
	f, err := os.Open(newBinary)
	if err != nil {
		return err
	}
	defer f.Close()
	staged := target + ".staged"
	if _, err := WriteVerified(f, staged, ""); err != nil {
		return err
	}
	newBinary = staged
	return os.Rename(newBinary, target)
}

// Reexec ersetzt den laufenden Prozess durch das (neue) Binary unter Executable().
// extraEnv wird an die Umgebung angehängt. Kehrt nur im Fehlerfall zurück.
func Reexec(extraEnv ...string) error {
	env := append(filterEnv(os.Environ(), extraEnv), extraEnv...)
	return syscall.Exec(exePath, os.Args, env)
}

func filterEnv(env, override []string) []string {
	keys := map[string]bool{}
	for _, e := range override {
		keys[strings.SplitN(e, "=", 2)[0]] = true
	}
	out := env[:0:0]
	for _, e := range env {
		if !keys[strings.SplitN(e, "=", 2)[0]] {
			out = append(out, e)
		}
	}
	return out
}

// ClearCloexec sorgt dafür, dass fd bei execve offen bleibt.
func ClearCloexec(fd uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// Release ist ein GitHub Release.
type Release struct {
	Tag    string
	Assets map[string]string // Name -> Download URL
	Sums   map[string]string // Name -> SHA256
}

// LatestRelease holt das neueste Release eines GitHub Repos (owner/name).
func LatestRelease(ctx context.Context, client *http.Client, repo string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api: HTTP %d", resp.StatusCode)
	}
	var body struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	rel := &Release{Tag: body.TagName, Assets: map[string]string{}, Sums: map[string]string{}}
	for _, a := range body.Assets {
		rel.Assets[a.Name] = a.URL
	}
	sumsURL, ok := rel.Assets["SHA256SUMS"]
	if !ok {
		return nil, errors.New("release enthält keine SHA256SUMS datei")
	}
	sreq, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return nil, err
	}
	sresp, err := client.Do(sreq)
	if err != nil {
		return nil, err
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SHA256SUMS: HTTP %d", sresp.StatusCode)
	}
	sc := bufio.NewScanner(sresp.Body)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			rel.Sums[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	return rel, sc.Err()
}
