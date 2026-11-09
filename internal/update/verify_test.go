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

// The "# tag" line names the release; checksums ignore it.
func TestSumsTag(t *testing.T) {
	sums := []byte("# tag v0.7.1-rc24\r\nabc  install.sh\n")
	if got := SumsTag(sums); got != "v0.7.1-rc24" {
		t.Fatalf("SumsTag %q", got)
	}
	if h, ok := SumFor(sums, "install.sh"); !ok || h != "abc" {
		t.Fatal("SumFor with a tag line")
	}
	if _, ok := SumFor(sums, "tag"); ok {
		t.Fatal("tag line taken for a file")
	}
	for _, c := range []struct {
		sums, tag string
		ok        bool
	}{
		{"# tag v1.2.3\nabc  x\n", "v1.2.3", true},
		{"# tag v1.2.2\nabc  x\n", "v1.2.3", false},
		{"abc  x\n", "v1.2.3", false},
		{"# tag v1.2.3\n# tag v1.2.4\n", "v1.2.3", false},
		{"# tag v1.2.3\n# tag v1.2.3\n", "v1.2.3", false},
		{"#tag v1.2.3\n", "v1.2.3", false},
		{"# tag v1.2.3-rc1\n", "v1.2.3", false},
	} {
		if err := CheckSumsTag([]byte(c.sums), c.tag); (err == nil) != c.ok {
			t.Errorf("%q for %s: err %v", c.sums, c.tag, err)
		}
	}
}
