package tunnel

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the real tor binary (skipped when it is not installed). They
// need no network: the control socket and the process loop work before tor
// has bootstrapped.

func realTorSpec(t *testing.T, isolate string, bridges []string) TorSpec {
	t.Helper()
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("tor not installed")
	}
	d, err := os.MkdirTemp("", "tt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return TorSpec{Name: "t", DataDir: filepath.Join(d, "data"), RunDir: d, Isolate: isolate, Bridges: bridges}
}

// Every torrc we generate must pass tor's own --verify-config.
func TestTorrcVerifiedByTor(t *testing.T) {
	for _, c := range []struct {
		isolate string
		bridges []string
	}{
		{"app", nil}, {"destination", nil}, {"none", nil},
		{"app", []string{"obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"}},
	} {
		spec := realTorSpec(t, c.isolate, c.bridges)
		fakePT(t, "lyrebird")
		tr := &Tor{spec: spec, dir: filepath.Join(spec.RunDir, "tor-t"), dnsPort: 15353}
		plugins, err := torPlugins(spec.Bridges)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.prepareDirs(); err != nil {
			t.Fatal(err)
		}
		rc, err := tr.torrc(plugins)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(tr.dir, "torrc")
		if err := os.WriteFile(p, []byte(rc), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(torPath(t), "--verify-config", "-f", p).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Configuration was valid") {
			t.Errorf("isolate=%q bridges=%v: tor rejects the torrc: %v\n%s\n%s", c.isolate, c.bridges, err, out, rc)
		}
	}
}

func torPath(t *testing.T) string {
	for _, p := range []string{"/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("tor binary not found")
	return ""
}

// StartTor: the process comes up, the control socket answers, NEWNYM works,
// a killed tor is restarted by the loop, Down ends it.
func TestRealTorLoop(t *testing.T) {
	spec := realTorSpec(t, "app", nil)
	old := torBinary
	torBinary = torPath(t)
	t.Cleanup(func() { torBinary = old })
	tr, err := StartTor(spec, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	if err != nil {
		t.Fatal(err)
	}
	down := false
	defer func() {
		if !down {
			tr.Down()
		}
	}()
	waitFor := func(what string, d time.Duration, f func() bool) {
		t.Helper()
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			if f() {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timeout: %s (err %q)", what, tr.Err())
	}
	waitFor("control socket", 30*time.Second, func() bool { _, err := tr.control("GETINFO version"); return err == nil })
	if !tr.Alive() {
		t.Error("not alive")
	}
	if err := tr.NewIdentity(); err != nil {
		t.Errorf("NEWNYM: %v", err)
	}
	if n := tr.Bootstrap(); n < 0 || n > 100 {
		t.Errorf("bootstrap %d", n)
	}
	// kill: the loop restarts it (first backoff 5 s)
	tr.mu.Lock()
	pid := tr.proc.Pid
	tr.mu.Unlock()
	_ = syscall.Kill(pid, syscall.SIGKILL)
	waitFor("restart", 40*time.Second, func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.running && tr.proc != nil && tr.proc.Pid != pid
	})
	waitFor("control socket after restart", 30*time.Second, func() bool { _, err := tr.control("GETINFO version"); return err == nil })
	tr.Down()
	down = true
	if tr.Alive() {
		t.Error("alive after Down")
	}
}
