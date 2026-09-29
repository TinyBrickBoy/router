package router

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestSetupScriptSyntax(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash fehlt")
	}
	for _, pin := range []string{"", "AbC+/123="} {
		var buf bytes.Buffer
		if err := setupTmpl.Execute(&buf, map[string]string{"Server": "https://router.example.com", "Token": "abc", "Pin": pin}); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = &buf
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("setup skript syntaxfehler (pin %q): %v\n%s", pin, err, out)
		}
	}
}
