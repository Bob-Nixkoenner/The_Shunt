package deb

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The postinst must not disable a tor service that was there before the
// package: the preinst leaves a marker, the postinst honours it.
func TestPostinstLeavesExistingTorAlone(t *testing.T) {
	b, err := os.ReadFile("build.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "systemctl disable --now tor.service")
	if i < 0 {
		t.Fatal("no tor disable found")
	}
	line := s[strings.LastIndex(s[:i], "\n\tif "):i]
	if !strings.Contains(line, "tor-was-installed") {
		t.Fatalf("tor disable is not guarded by the marker: %q", line)
	}
	if !strings.Contains(s, `DEBIAN/preinst`) || !strings.Contains(s, "db:Status-Status") {
		t.Fatal("preinst that records an existing tor is missing")
	}
	// the generated scripts must parse
	for _, name := range []string{"preinst", "postinst"} {
		start := strings.Index(s, `cat >"$P/DEBIAN/`+name+`" <<'EOF'`)
		if start < 0 {
			t.Fatal(name, "not found")
		}
		body := s[start:]
		body = body[strings.Index(body, "\n")+1:]
		body = body[:strings.Index(body, "\nEOF\n")]
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
	}
}
