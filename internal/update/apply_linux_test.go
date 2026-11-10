package update

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The root side checks the hash again on its own copy and runs only that.
func TestRootScript(t *testing.T) {
	d := t.TempDir()
	out := filepath.Join(d, "ran")
	inst := filepath.Join(d, "install.sh")
	body := "echo \"$SHUNT_REF $SHUNT_YES $(dirname \"$0\")\" >" + out + "\n"
	os.WriteFile(inst, []byte(body), 0o600)
	h := sha256.Sum256([]byte(body))
	good := hex.EncodeToString(h[:])

	args := installerArgs(inst, good, "v1.2.3")
	if b, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("good installer: %v %s", err, b)
	}
	got, _ := os.ReadFile(out)
	f := strings.Fields(string(got))
	if len(f) != 3 || f[0] != "v1.2.3" || f[1] != "1" || filepath.Dir(f[2]) == d || f[2] == "/tmp" {
		t.Fatalf("ran as %q", got)
	}
	if _, err := os.Stat(f[2]); !os.IsNotExist(err) {
		t.Fatalf("private dir %s left behind", f[2])
	}

	os.Remove(out)
	args = installerArgs(inst, strings.Repeat("0", 64), "v1.2.3")
	b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err == nil || !strings.Contains(string(b), "does not match") {
		t.Fatalf("wrong hash: %v %s", err, b)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("installer ran despite the wrong hash")
	}
}
