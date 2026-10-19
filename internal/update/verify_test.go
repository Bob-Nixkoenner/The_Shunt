package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signs with the real ssh-keygen, so the format is the one releases use
func TestVerifySSHSig(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen")
	}
	d := t.TempDir()
	key := filepath.Join(d, "k")
	if out, err := exec.Command(kg, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	sums := filepath.Join(d, "SHA256SUMS")
	os.WriteFile(sums, []byte("abc  a.apk\n"), 0o600)
	if out, err := exec.Command(kg, "-Y", "sign", "-q", "-f", key, "-n", ReleaseNamespace, sums).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	sig, _ := os.ReadFile(sums + ".sig")
	pubLine, _ := os.ReadFile(key + ".pub")
	pub := strings.Fields(string(pubLine))[1]
	msg, _ := os.ReadFile(sums)
	if err := verifySSHSig(msg, sig, pub, ReleaseNamespace); err != nil {
		t.Fatalf("good signature rejected: %v", err)
	}
	if err := verifySSHSig(append(msg, 'x'), sig, pub, ReleaseNamespace); err == nil {
		t.Fatal("changed message accepted")
	}
	if err := verifySSHSig(msg, sig, pub, "other"); err == nil {
		t.Fatal("wrong namespace accepted")
	}
	if err := VerifySums(msg, sig); err == nil {
		t.Fatal("foreign key accepted as release key")
	}
	if h, ok := SumFor([]byte("ABC  *a.apk\n"), "a.apk"); !ok || h != "abc" {
		t.Fatal("SumFor")
	}
}
