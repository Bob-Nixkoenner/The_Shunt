package fdroid

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// run builds a repo with a fake fdroid tool and reports the output tree.
func run(t *testing.T, fdroidBody string) (out string, err error) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "fdroid"), []byte("#!/bin/sh\n"+fdroidBody), 0o755)
	apk := filepath.Join(dir, "app-1.apk")
	os.WriteFile(apk, []byte("apk"), 0o644)
	ks := filepath.Join(dir, "ks")
	os.WriteFile(ks, []byte("key"), 0o600)
	tmp := filepath.Join(dir, "tmp")
	os.Mkdir(tmp, 0o755)
	out = filepath.Join(dir, "out")
	cmd := exec.Command("bash", "build-repo.sh", apk, out)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp,
		"FDROID_KEYSTORE="+ks, "FDROID_KEYSTORE_PASSWORD=synthetic-secret", "FDROID_REPO_URL=https://repo.invalid/r", "ANDROID_HOME=/nonexistent")
	_, err = cmd.CombinedOutput()
	// nothing of the work directory may stay behind
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("work directory left behind: %v", left)
	}
	return out, err
}

func noSecrets(t *testing.T, out string) {
	filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(p, "keystore") || strings.Contains(p, "config.yml") || strings.Contains(string(b), "synthetic-secret") {
			t.Errorf("secret in the output tree: %s", p)
		}
		return nil
	})
}

func TestBuildRepoKeepsKeyOutOfOutput(t *testing.T) {
	out, _ := run(t, "echo index > repo/index-v1.json\n")
	noSecrets(t, out)
	if _, err := os.Stat(filepath.Join(out, "repo", "index-v1.json")); err != nil {
		t.Fatal("index not handed over:", err)
	}
	// a failing fdroid: nothing secret, no work directory left
	out, _ = run(t, "exit 3\n")
	noSecrets(t, out)
}
