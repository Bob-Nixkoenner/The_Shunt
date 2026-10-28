package racebpf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
	"golang.org/x/sys/unix"
)

func TestKey(t *testing.T) {
	k := key("firefox")
	if string(k[:7]) != "firefox" || k[7] != 0 || k[15] != 0 {
		t.Errorf("%q", k)
	}
	if k := key("a-very-long-program-name"); k[15] != 0 || string(k[:15]) != "a-very-long-pro" {
		t.Errorf("%q", k)
	}
}

func TestInstructionsAssemble(t *testing.T) {
	insns := instructions(3, 2, 12345)
	if err := insns.Marshal(nopWriter{}, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
}

// TestStart loads and attaches the program for real (root only): a socket
// created by this process (outside the given cgroup) gets the mark.
func TestStart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	mount, err := cgroup.Mount()
	if err != nil {
		t.Skip(err)
	}
	root := "shunt-racebpf-test"
	if err := os.Mkdir(filepath.Join(mount, root), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join(mount, root))
	g, err := Start(mount, root)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	comm, _ := os.ReadFile("/proc/self/comm")
	name := string(comm[:len(comm)-1])
	if err := g.SetMarks(map[string]uint32{name: 0x5a5a0000}); err != nil {
		t.Fatal(err)
	}
	if got := socketMark(t); got != 0x5a5a0000 {
		t.Errorf("mark %#x", got)
	}
	if err := g.SetMarks(nil); err != nil {
		t.Fatal(err)
	}
	if got := socketMark(t); got != 0 {
		t.Errorf("mark after removal %#x", got)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func socketMark(t *testing.T) uint32 {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	m, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(m)
}
