package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake release: files by name, SHA256SUMS signed with a
// fresh key that the test makes the release key (when sign is true). The
// list names release v1.2.3 ("# tag" line) unless sumsFor has the key
// "# tag": its value is named instead ("" = no such line).
func release(t *testing.T, files map[string]string, sumsFor map[string]string, sign bool) {
	t.Helper()
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen")
	}
	d := t.TempDir()
	key := filepath.Join(d, "k")
	if out, err := exec.Command(kg, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	var sums strings.Builder
	tag, ok := sumsFor["# tag"]
	if !ok {
		tag = "v1.2.3"
	}
	if tag != "" {
		sums.WriteString("# tag " + tag + "\n")
	}
	for name, content := range sumsFor {
		if name == "# tag" {
			continue
		}
		h := sha256.Sum256([]byte(content))
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	sp := filepath.Join(d, "SHA256SUMS")
	os.WriteFile(sp, []byte(sums.String()), 0o600)
	if out, err := exec.Command(kg, "-Y", "sign", "-q", "-f", key, "-n", ReleaseNamespace, sp).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	sig, _ := os.ReadFile(sp + ".sig")
	files["SHA256SUMS"] = sums.String()
	files["SHA256SUMS.sig"] = string(sig)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(c))
	}))
	t.Cleanup(srv.Close)
	oldBase, oldSigner := releaseBase, releaseSigner
	releaseBase = srv.URL + "/"
	if sign {
		pub, _ := os.ReadFile(key + ".pub")
		releaseSigner = strings.Fields(string(pub))[1]
	}
	t.Cleanup(func() { releaseBase, releaseSigner = oldBase, oldSigner })
}

const script = "#!/bin/bash\necho installer\n"

// Only an installer the release key signed is handed out.
func TestDownloadInstaller(t *testing.T) {
	ctx := context.Background()
	t.Run("signed", func(t *testing.T) {
		release(t, map[string]string{"install.sh": script}, map[string]string{"install.sh": script}, true)
		path, sum, err := download(ctx, "v1.2.3", "install.sh")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(filepath.Dir(path))
		if b, _ := os.ReadFile(path); string(b) != script || len(sum) != 64 {
			t.Fatalf("got %q %q", b, sum)
		}
	})
	for _, c := range []struct {
		name  string
		files map[string]string
		sums  map[string]string
		sign  bool
		want  string
	}{
		{"foreign key", map[string]string{"install.sh": script}, map[string]string{"install.sh": script}, false, "another key"},
		{"tampered", map[string]string{"install.sh": script + "rm -rf /\n"}, map[string]string{"install.sh": script}, true, "does not match"},
		{"not listed", map[string]string{"install.sh": script}, map[string]string{"shunt.tar.gz": "x"}, true, "has no install.sh"},
		{"other release", map[string]string{"install.sh": script}, map[string]string{"install.sh": script, "# tag": "v1.0.0"}, true, "belong to release v1.0.0, not v1.2.3"},
		{"release not named", map[string]string{"install.sh": script}, map[string]string{"install.sh": script, "# tag": ""}, true, "do not name release v1.2.3"},
		{"named twice", map[string]string{"install.sh": script}, map[string]string{"install.sh": script, "# tag": "v1.2.3\n# tag v1.2.3"}, true, "do not name release"},
	} {
		t.Run(c.name, func(t *testing.T) {
			release(t, c.files, c.sums, c.sign)
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			path, _, err := download(ctx, "v1.2.3", "install.sh")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if path != "" {
				t.Fatalf("path %q handed out", path)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Fatalf("left behind: %v", left)
			}
		})
	}
}
