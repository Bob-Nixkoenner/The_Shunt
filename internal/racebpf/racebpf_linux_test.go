package racebpf

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"
	"github.com/cilium/ebpf/asm"
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

// The map value layouts must match what the programs read and write.
func TestValueSizes(t *testing.T) {
	if n := binary.Size(nameVal{}); n != 8 {
		t.Errorf("nameVal %d", n)
	}
	if n := binary.Size(procVal{}); n != 16 {
		t.Errorf("procVal %d", n)
	}
	if n := binary.Size(stateVal{}); n != 16 {
		t.Errorf("stateVal %d", n)
	}
	if v := (Entry{Mark: 7}).value(); v != (nameVal{Mark: 7, Kind: KindMark}) {
		t.Errorf("%+v", v)
	}
	if v := (Entry{Mark: 7, Hold: true}).value(); v != (nameVal{Kind: KindHold}) {
		t.Errorf("hold must not carry a mark: %+v", v)
	}
}

// All programs assemble: every jump finds its label (the verifier itself
// only runs with root, see TestStart).
func TestInstructionsAssemble(t *testing.T) {
	fd := fds{3, 4, 5, 6}
	for name, insns := range map[string]asm.Instructions{
		"sock": sockInsns(fd, 2, 12345, uint64(HoldMax)),
		"exec": execInsns(fd),
		"fork": forkInsns(fd, defaultForkChildOff),
		"exit": exitInsns(fd),
	} {
		if err := insns.Marshal(nopWriter{}, binary.LittleEndian); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// stack slots stay inside the 512 byte frame and do not overlap
		for _, in := range insns {
			if in.Src == asm.RFP || in.Dst == asm.RFP {
				if in.Offset < -512 || in.Offset > 0 {
					t.Errorf("%s: stack offset %d", name, in.Offset)
				}
			}
		}
	}
}

func TestParseFieldOffset(t *testing.T) {
	format := `name: sched_process_fork
ID: 312
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:char parent_comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t parent_pid;	offset:24;	size:4;	signed:1;
	field:char child_comm[16];	offset:28;	size:16;	signed:0;
	field:pid_t child_pid;	offset:44;	size:4;	signed:1;
`
	off, ok := parseFieldOffset(bufio.NewScanner(strings.NewReader(format)), "child_pid")
	if !ok || off != 44 {
		t.Errorf("got %d %v", off, ok)
	}
	if _, ok := parseFieldOffset(bufio.NewScanner(strings.NewReader(format)), "pid"); ok {
		t.Error("common_pid must not count as pid")
	}
	// a __data_loc comm moves child_pid
	moved := strings.Replace(format, "offset:44;", "offset:20;", 1)
	if off, _ := parseFieldOffset(bufio.NewScanner(strings.NewReader(moved)), "child_pid"); off != 20 {
		t.Errorf("got %d", off)
	}
}

// TestStart loads and attaches the programs for real (root only).
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
	if g.Partial != nil {
		t.Fatalf("tracepoints: %v", g.Partial)
	}
	comm, _ := os.ReadFile("/proc/self/comm")
	name := string(comm[:len(comm)-1])

	// comm table: this process is older than the guard
	if err := g.SetEntries(map[string]Entry{name: {Mark: 0x5a5a0000}}); err != nil {
		t.Fatal(err)
	}
	if got := socketMark(t); got != 0x5a5a0000 {
		t.Errorf("mark %#x", got)
	}
	// exec: a fresh child gets the mark from its process state
	if out := child(t); out != "mark 0x5a5a0000" {
		t.Errorf("child: %s", out)
	}
	// hold: the fresh child's socket is refused
	if err := g.SetEntries(map[string]Entry{name: {Hold: true}}); err != nil {
		t.Fatal(err)
	}
	if out := child(t); out != "refused" {
		t.Errorf("held child: %s", out)
	}
	if got := socketMark(t); got != 0 {
		t.Errorf("a held name gives no comm mark: %#x", got)
	}
	if s := g.Stats(); s[StatMarked] == 0 || s[StatHeld] == 0 || s[StatComm] == 0 {
		t.Errorf("stats %v", s)
	}
	if err := g.SetEntries(nil); err != nil {
		t.Fatal(err)
	}
	if got := socketMark(t); got != 0 {
		t.Errorf("mark after removal %#x", got)
	}
}

// child re-runs the test binary, which reports its first socket's fate.
func child(t *testing.T) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSocket$")
	cmd.Env = append(os.Environ(), "SHUNT_RACEBPF_HELPER=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	s := string(out)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func TestHelperSocket(t *testing.T) {
	if os.Getenv("SHUNT_RACEBPF_HELPER") != "1" {
		t.Skip("helper for TestStart")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if errors.Is(err, unix.EPERM) {
		fmt.Println("refused")
		return
	}
	if err != nil {
		fmt.Println("error", err)
		return
	}
	defer unix.Close(fd)
	m, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	fmt.Printf("mark %#x\n", uint32(m))
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
