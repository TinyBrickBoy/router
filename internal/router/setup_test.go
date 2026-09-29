package router

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestSetupScriptSyntax(t *testing.T) {
	var buf bytes.Buffer
	if err := setupTmpl.Execute(&buf, map[string]string{"Server": "https://router.example.com", "Token": "abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash fehlt")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup skript syntaxfehler: %v\n%s", err, out)
	}
}
