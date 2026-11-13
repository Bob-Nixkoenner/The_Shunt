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
	"sync"
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
		"sock":     sockInsns(fd, 2, 12345, uint64(HoldMax)),
		"exec":     execInsns(fd),
		"fork":     forkInsns(fd, defaultForkChildOff),
		"fork-raw": forkRawInsns(fd, 2400),
		"exit":     exitInsns(fd),
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

var rawLimited string

// TestStartRaw: the same with raw tracepoints (Debian: no perf events
// without CAP_SYS_ADMIN).
func TestStartRaw(t *testing.T) {
	forceRaw = true
	defer func() { forceRaw = false }()
	TestStart(t)
	// children: only when the kernel lets a non-GPL program read the child's pid
	t.Log("raw tracepoints loaded; fork program GPL-restricted:", rawLimited)
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
	rawLimited = g.Limited
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

func TestParseCapEff(t *testing.T) {
	got, err := parseCapEff("Name:\tshuntd\nCapPrm:\t0000000000003000\nCapEff:\t000000c000001000\n")
	if err != nil || got != 0xc000001000 {
		t.Fatalf("got %x %v", got, err)
	}
	if _, err := parseCapEff("Name:\tx\n"); err == nil {
		t.Fatal("no CapEff line accepted")
	}
}

// stubPrepare swaps the process-wide steps of prepare for one test.
func stubPrepare(t *testing.T, caps uint64, capsErr, memlock error) *int {
	t.Helper()
	oldCaps, oldRm, oldNS := effectiveCaps, removeMemlock, hostUserNS
	calls := 0
	hostUserNS = func() bool { return true }
	effectiveCaps = func() (uint64, error) { return caps, capsErr }
	removeMemlock = func() error { calls++; return memlock }
	memlockOnce, memlockErr = sync.Once{}, nil
	t.Cleanup(func() {
		effectiveCaps, removeMemlock, hostUserNS = oldCaps, oldRm, oldNS
		memlockOnce, memlockErr = sync.Once{}, nil
	})
	return &calls
}

// Without CAP_BPF and CAP_SYS_ADMIN (the bounding set of a wrapper or an
// old unit) Start must say so instead of cilium's "MEMLOCK may be too low",
// and must not touch the memlock limit.
func TestPrepareWithoutCaps(t *testing.T) {
	calls := stubPrepare(t, 1<<12|1<<0, nil, nil) // CAP_NET_ADMIN + CAP_CHOWN only
	if _, err := prepare(); !errors.Is(err, ErrNoCaps) {
		t.Fatalf("got %v, want ErrNoCaps", err)
	}
	if *calls != 0 {
		t.Fatal("memlock lifted without caps")
	}
	mnt := t.TempDir()
	if err := os.Mkdir(filepath.Join(mnt, "shunt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(mnt, "shunt"); !errors.Is(err, ErrNoCaps) {
		t.Fatalf("Start: got %v, want ErrNoCaps", err)
	}
}

func TestPrepareLiftsMemlockOnce(t *testing.T) {
	for _, c := range []uint64{1 << capBPF, 1 << capSysAdmin} {
		calls := stubPrepare(t, c, nil, nil)
		for range 3 {
			if ml, err := prepare(); ml != nil || err != nil {
				t.Fatalf("caps %x: %v %v", c, ml, err)
			}
		}
		if *calls != 1 {
			t.Fatalf("caps %x: RemoveMemlock called %d times, want once", c, *calls)
		}
	}
	// unreadable caps: let the kernel decide
	stubPrepare(t, 0, errors.New("no /proc"), nil)
	if _, err := prepare(); err != nil {
		t.Fatal(err)
	}
}

// A failed lift is kept and named by a later EPERM, nothing else.
func TestMemlockFailureNamedOnEPERM(t *testing.T) {
	lift := errors.New("setrlimit: operation not permitted")
	stubPrepare(t, 1<<capBPF, nil, lift)
	ml, err := prepare()
	if err != nil || ml != lift {
		t.Fatalf("got %v %v", ml, err)
	}
	if e := mapError("shunt_names", fmt.Errorf("map create: %w", unix.EPERM), ml); !errors.Is(e, ErrMemlock) || !strings.Contains(e.Error(), "LimitMEMLOCK") {
		t.Fatalf("EPERM: %v", e)
	}
	if e := mapError("shunt_names", unix.EINVAL, ml); errors.Is(e, ErrMemlock) {
		t.Fatalf("EINVAL called memlock: %v", e)
	}
	if e := mapError("shunt_names", unix.EPERM, nil); errors.Is(e, ErrMemlock) {
		t.Fatalf("lifted limit called memlock: %v", e)
	}
}

// An unprivileged container (CT130) has every capability in its own user
// namespace, but the kernel refuses bpf() there all the same.
func TestPrepareInContainer(t *testing.T) {
	calls := stubPrepare(t, 1<<capBPF|1<<capSysAdmin, nil, nil)
	hostUserNS = func() bool { return false }
	if _, err := prepare(); !errors.Is(err, ErrUserNS) {
		t.Fatalf("got %v, want ErrUserNS", err)
	}
	if *calls != 0 {
		t.Fatal("memlock lifted in a container")
	}
	for m, want := range map[string]bool{
		"         0          0 4294967295\n": true,
		"         0     100000      65536\n": false,
		"0 0 4294967295\n1 2 3\n":            false,
		"":                                   false,
	} {
		if fullUIDMap(m) != want {
			t.Errorf("%q: got %v", m, !want)
		}
	}
}
