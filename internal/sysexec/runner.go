// Package sysexec führt Systembefehle aus und unterstützt einen Dry-Run Modus.
package sysexec

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner führt Befehle aus. Im DryRun Modus werden Befehle nur protokolliert.
type Runner struct {
	DryRun bool
	Logger *log.Logger
	// Verbose protokolliert auch ausgeführte Befehle.
	Verbose bool
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Run führt einen verändernden Befehl aus.
func (r *Runner) Run(name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if r.DryRun {
		r.logf("[dry-run] %s", line)
		return "", nil
	}
	if r.Verbose {
		r.logf("exec: %s", line)
	}
	return r.exec(name, args...)
}

// Query führt einen lesenden Befehl aus. Im DryRun Modus wird eine leere Ausgabe geliefert.
func (r *Runner) Query(name string, args ...string) (string, error) {
	if r.DryRun {
		return "", nil
	}
	return r.exec(name, args...)
}

func (r *Runner) exec(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.String(), nil
}

// WriteFile schreibt eine Datei atomar (tmp + rename).
func (r *Runner) WriteFile(path string, data []byte, perm os.FileMode) error {
	if r.DryRun {
		r.logf("[dry-run] schreibe %s (%d Bytes)", path, len(data))
		return nil
	}
	return WriteFileAtomic(path, data, perm)
}

// WriteFileAtomic schreibt eine Datei atomar.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
