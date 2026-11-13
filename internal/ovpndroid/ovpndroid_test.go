//go:build linux

package ovpndroid

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With OVPN_FAKE set this test binary plays openvpn: it reads --config,
// writes what it read to $OVPN_FAKE (so the test can compare it), connects
// to the management socket (unless OVPN_FAKE_NOMGMT=1) and stays until the
// socket closes or SIGTERM comes over it.
func TestMain(m *testing.M) {
	if out := os.Getenv("OVPN_FAKE"); out != "" {
		fakeOpenVPN(out)
		return
	}
	os.Exit(m.Run())
}

func fakeOpenVPN(out string) {
	var conf, sock string
	for i, a := range os.Args {
		if i+1 >= len(os.Args) {
			break
		}
		switch a {
		case "--config":
			conf = os.Args[i+1]
		case "--management":
			sock = os.Args[i+1]
		}
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		os.Exit(2)
	}
	os.WriteFile(out, b, 0o600)
	if os.Getenv("OVPN_FAKE_NOMGMT") == "1" {
		os.Exit(1) // dies before the management connection (bad option, …)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		os.Exit(3)
	}
	c.Write([]byte(">HOLD:Waiting for hold release:0\n"))
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			os.Exit(0)
		}
		if strings.Contains(string(buf[:n]), "signal SIGTERM") {
			os.Exit(0)
		}
	}
}

const secretConf = "client\nremote 192.0.2.1 1194\n<key>\nPRIVATE KEY MATERIAL\n</key>\n"

func waitGone(t *testing.T, f string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still exists", f)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The config with the keys exists only until openvpn read it.
func TestConfigWipedAfterStart(t *testing.T) {
	exe, _ := os.Executable()
	seen := filepath.Join(t.TempDir(), "seen")
	t.Setenv("OVPN_FAKE", seen)
	dir := filepath.Join(t.TempDir(), "openvpn", "o")
	tun, err := Start(Options{Exe: exe, Config: secretConf, Dir: dir, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	conf := filepath.Join(dir, ConfName)
	waitGone(t, conf, 5*time.Second)
	b, _ := os.ReadFile(seen)
	if string(b) != secretConf {
		t.Errorf("openvpn read %q", b)
	}
	select {
	case <-tun.Done():
		t.Fatalf("openvpn ended: %v", tun.Err())
	default:
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		t.Errorf("left in the work folder: %s", e.Name())
	}
	tun.Close()
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Errorf("config back after Close: %v", err)
	}
}

// openvpn dies before it connects: the config goes too.
func TestConfigWipedWhenOpenVPNDies(t *testing.T) {
	exe, _ := os.Executable()
	t.Setenv("OVPN_FAKE", filepath.Join(t.TempDir(), "seen"))
	t.Setenv("OVPN_FAKE_NOMGMT", "1")
	dir := t.TempDir()
	tun, err := Start(Options{Exe: exe, Config: secretConf, Dir: dir, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-tun.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("not done")
	}
	if _, err := os.Stat(filepath.Join(dir, ConfName)); !os.IsNotExist(err) {
		t.Errorf("config left after openvpn died: %v", err)
	}
}

// openvpn cannot be started at all: no config file left behind.
func TestConfigWipedWhenStartFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Start(Options{Exe: filepath.Join(dir, "missing"), Config: secretConf, Dir: dir}); err == nil {
		t.Fatal("started a missing program")
	}
	if _, err := os.Stat(filepath.Join(dir, ConfName)); !os.IsNotExist(err) {
		t.Errorf("config left: %v", err)
	}
}

// Rests of a crashed run are wiped: by CleanStale and by the next Start.
func TestCleanStale(t *testing.T) {
	base := t.TempDir()
	for _, n := range []string{"a", "b"} {
		os.MkdirAll(filepath.Join(base, n), 0o700)
		os.WriteFile(filepath.Join(base, n, ConfName), []byte(secretConf), 0o600)
	}
	if n := CleanStale(base); n != 2 {
		t.Errorf("cleaned %d", n)
	}
	for _, n := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(base, n, ConfName)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", n, err)
		}
	}
	if CleanStale("") != 0 {
		t.Error("empty base")
	}
}
