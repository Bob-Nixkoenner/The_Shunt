// Package racebpf closes the start race of app rules: between a program's
// exec and the moment the app watcher has moved it into its rule's cgroup,
// its sockets would take the default route (lab tests A02/A06/A07, M04).
// nftables matches the cgroup a socket was *created* in, so a socket made
// in that window keeps the default route for its whole life.
//
// Four small eBPF programs, written with cilium/ebpf's assembler (building
// needs no clang):
//
//   - tracepoint sched/sched_process_exec: runs inside execve, before the
//     new program's first instruction. If its name (comm) has an entry,
//     the process gets a start state (mark or hold) keyed by its tgid.
//   - tracepoint sched/sched_process_fork: a child inherits its parent's
//     state (a script that starts dig before the watcher moved the script:
//     dig belongs to the script's rule, as it would inside the cgroup).
//     An exec without an own entry keeps the inherited state, like a cgroup.
//   - tracepoint sched/sched_process_exit: forgets the task.
//   - cgroup/sock_create on the root cgroup: a process outside shuntd's
//     cgroup tree with a start state gets its rule's route mark on the
//     socket (nft.Render keeps a Shunt mark already set), or, while held,
//     the socket is refused (EPERM) until the watcher has decided. Holds
//     end after HoldMax at the latest (then the old behaviour). Processes
//     that started before the guard was loaded fall back to the comm table.
//
// Once a program is in its group, its new sockets are left alone and all
// rules apply as usual. shuntd, its tunnels and tor run inside shuntd's
// tree and are never touched; forwarded traffic (gateway mode) has no
// local sockets. Everything is detached when shuntd exits (the links die
// with the process). Without eBPF (old kernel: bpf_get_current_pid_tgid and
// bpf_get_current_comm in cgroup programs are certain from 6.1 on; no
// tracefs; no CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON) shuntd works as before
// and warns in status and check.
package racebpf

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// MaxNames is the size of the name map, MaxProcs of the per-process maps
// (LRU: the oldest entries go first when full).
const (
	MaxNames = 1024
	MaxProcs = 32768
)

// HoldMax is the longest a held program's sockets are refused when the
// watcher never decides (missed event): then the socket is allowed.
const HoldMax = 2 * time.Second

// Entry kinds (value of the name and state maps).
const (
	KindMark = 1
	KindHold = 2
)

// Counters in the stats map.
const (
	StatMarked  = iota // socket marked from the process state
	StatHeld           // socket refused (held)
	StatExpired        // hold ran out: socket allowed with the default route
	StatComm           // socket marked from the comm table (process older than the guard)
	numStats
)

// offset of mark in struct bpf_sock (bound_dev_if, family, type, protocol, mark)
const sockMarkOff = 16

// child_pid in sched_process_fork (common fields 8, parent_comm[16],
// parent_pid, child_comm[16], child_pid); read from tracefs when possible.
const defaultForkChildOff = 44

// Entry is a name's start entry.
type Entry struct {
	Mark uint32
	Hold bool
}

func (e Entry) value() nameVal {
	if e.Hold {
		return nameVal{Kind: KindHold}
	}
	return nameVal{Mark: e.Mark, Kind: KindMark}
}

type nameVal struct{ Mark, Kind uint32 }

// procVal: procs map value (key: tid/tgid). Gen tells a reused pid apart.
type procVal struct {
	Origin uint32
	_      uint32
	Gen    uint64
}

// stateVal: state map value (key: the tgid whose exec created it).
type stateVal struct {
	Mark, Kind uint32
	Gen        uint64 // bpf_ktime_get_ns at the exec (CLOCK_MONOTONIC)
}

type bpfMaps struct{ names, procs, state, stats *ebpf.Map }

// Guard is the loaded and attached program set.
type Guard struct {
	m     bpfMaps
	progs []*ebpf.Program
	links []link.Link
	// Partial: the tracepoints could not be loaded or attached (no tracefs,
	// perf_event_open filtered …): only the name table at socket creation
	// works, without threads, children and holds.
	Partial error
	// Raw: the tracepoints are raw ones (no perf events allowed).
	Raw bool
	// Limited: loaded, but without part of the coverage (why).
	Limited string
}

// attachTracepoints loads and attaches exec/fork/exit; on error none stays.
func (g *Guard) attachTracepoints(fd fds) (err error) {
	nl := len(g.links)
	defer func() {
		if err != nil {
			for _, l := range g.links[nl:] {
				l.Close()
			}
			g.links = g.links[:nl]
		}
	}()
	load := func(name string, insns asm.Instructions) (*ebpf.Program, error) {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.TracePoint, License: "Apache-2.0", Instructions: insns})
		if err != nil {
			return nil, fmt.Errorf("program %s: %w", name, err)
		}
		g.progs = append(g.progs, p)
		return p, nil
	}
	if forceRaw {
		return g.attachRawTracepoints(fd)
	}
	exec, err := load("shunt_exec", execInsns(fd))
	if err != nil {
		return err
	}
	fork, err := load("shunt_fork", forkInsns(fd, forkChildOffset()))
	if err != nil {
		return err
	}
	exit, err := load("shunt_exit", exitInsns(fd))
	if err != nil {
		return err
	}
	// exit and fork before exec: a child forked between the attaches must
	// not miss its parent's state
	for _, tp := range []struct {
		name string
		p    *ebpf.Program
	}{{"sched_process_exit", exit}, {"sched_process_fork", fork}, {"sched_process_exec", exec}} {
		l, err := link.Tracepoint("sched", tp.name, tp.p, nil)
		if err != nil {
			// Debian kernels (perf_event_paranoid=3) refuse perf_event_open
			// without CAP_SYS_ADMIN, CAP_PERFMON is not enough: raw
			// tracepoints need no perf event
			for _, l := range g.links[nl:] {
				l.Close()
			}
			g.links = g.links[:nl]
			if rerr := g.attachRawTracepoints(fd); rerr != nil {
				return fmt.Errorf("attach %s: %w (raw tracepoints: %v)", tp.name, err, rerr)
			}
			return nil
		}
		g.links = append(g.links, l)
	}
	return nil
}

// attachRawTracepoints is attachTracepoints without perf events
// (BPF_RAW_TRACEPOINT_OPEN). exec and exit only ask about the current task;
// fork reads the child's pid from its task_struct (args[1]), offset from the
// kernel's BTF.
func (g *Guard) attachRawTracepoints(fd fds) error {
	off, err := taskPidOffset()
	if err != nil {
		return err
	}
	nl := len(g.links)
	ok := false
	defer func() {
		if !ok {
			for _, l := range g.links[nl:] {
				l.Close()
			}
			g.links = g.links[:nl]
		}
	}()
	for _, tp := range []struct {
		name, prog string
		insns      asm.Instructions
	}{
		{"sched_process_exit", "shunt_exit_raw", exitInsns(fd)},
		{"sched_process_fork", "shunt_fork_raw", forkRawInsns(fd, off)},
		{"sched_process_exec", "shunt_exec_raw", execInsns(fd)},
	} {
		license := "Apache-2.0"
		if tp.name == "sched_process_fork" {
			// bpf_probe_read_kernel (the child's pid) is GPL-only: this one
			// program is dual licensed for the kernel (decided 09.11.2026)
			license = "Dual MIT/GPL"
		}
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: tp.prog, Type: ebpf.RawTracepoint, License: license, Instructions: tp.insns})
		if err != nil && tp.name == "sched_process_fork" {
			// still refused: children inherit nothing (threads still count:
			// sockets are matched by tgid; children that exec a program of
			// a rule get its entry)
			g.Limited = fmt.Sprintf("raw tracepoints, children not inherited: %v", err)
			continue
		}
		if err != nil {
			return fmt.Errorf("program %s: %w", tp.prog, err)
		}
		g.progs = append(g.progs, p)
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: p})
		if err != nil {
			return fmt.Errorf("attach %s: %w", tp.name, err)
		}
		g.links = append(g.links, l)
	}
	ok = true
	g.Raw = true
	return nil
}

// forceRaw: tests take the raw tracepoint path.
var forceRaw bool

// taskPidOffset: byte offset of pid (the thread id) in struct task_struct.
func taskPidOffset() (int32, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("kernel BTF: %w", err)
	}
	var ts *btf.Struct
	if err := spec.TypeByName("task_struct", &ts); err != nil {
		return 0, fmt.Errorf("kernel BTF: %w", err)
	}
	for _, m := range ts.Members {
		if m.Name == "pid" && m.BitfieldSize == 0 && m.Offset%32 == 0 {
			return int32(m.Offset.Bytes()), nil
		}
	}
	return 0, errors.New("kernel BTF: no task_struct.pid")
}

// Start loads the programs and attaches them. root is shuntd's cgroup
// (relative to the cgroup2 mount): processes below it are left alone.
func Start(mount, root string) (g *Guard, err error) {
	if strings.Trim(root, "/") == "" {
		return nil, errors.New("shuntd runs in the root cgroup")
	}
	fi, err := os.Stat(filepath.Join(mount, root))
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("no inode for the cgroup")
	}
	// a cgroup's id is the inode of its directory; level 0 is the root
	id, level := st.Ino, int32(len(strings.Split(strings.Trim(root, "/"), "/")))

	g = &Guard{}
	defer func() {
		if err != nil {
			g.Close()
			g = nil
		}
	}()
	newMap := func(name string, t ebpf.MapType, k, v, n uint32) (*ebpf.Map, error) {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Name: name, Type: t, KeySize: k, ValueSize: v, MaxEntries: n})
		if err != nil {
			return nil, fmt.Errorf("map %s: %w", name, err)
		}
		return m, nil
	}
	if g.m.names, err = newMap("shunt_names", ebpf.Hash, 16, 8, MaxNames); err != nil {
		return
	}
	if g.m.procs, err = newMap("shunt_procs", ebpf.LRUHash, 4, 16, MaxProcs); err != nil {
		return
	}
	if g.m.state, err = newMap("shunt_state", ebpf.LRUHash, 4, 16, MaxProcs); err != nil {
		return
	}
	if g.m.stats, err = newMap("shunt_stats", ebpf.Array, 4, 8, numStats); err != nil {
		return
	}
	load := func(name string, t ebpf.ProgramType, at ebpf.AttachType, insns asm.Instructions) (*ebpf.Program, error) {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: t, AttachType: at, License: "Apache-2.0", Instructions: insns})
		if err != nil {
			return nil, fmt.Errorf("program %s: %w", name, err)
		}
		g.progs = append(g.progs, p)
		return p, nil
	}
	fd := g.m.fds()
	// the sock program first: the tracepoints only fill maps it reads
	sock, err := load("shunt_sock", ebpf.CGroupSock, ebpf.AttachCGroupInetSockCreate, sockInsns(fd, level, id, uint64(HoldMax)))
	if err != nil {
		return
	}
	g.Partial = g.attachTracepoints(fd)
	// on error sockets are still marked by name (the guard of old):
	// better than nothing; the daemon reports the reason
	l, err := link.AttachCgroup(link.CgroupOptions{Path: mount, Attach: ebpf.AttachCGroupInetSockCreate, Program: sock})
	if err != nil {
		return g, fmt.Errorf("attach sock_create: %w", err)
	}
	g.links = append(g.links, l)
	return g, nil
}

type fds struct{ names, procs, state, stats int }

func (m bpfMaps) fds() fds {
	return fds{m.names.FD(), m.procs.FD(), m.state.FD(), m.stats.FD()}
}

// forkChildOffset reads child_pid's offset from the tracepoint's format.
func forkChildOffset() int16 {
	for _, dir := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		f, err := os.Open(filepath.Join(dir, "events/sched/sched_process_fork/format"))
		if err != nil {
			continue
		}
		off, ok := parseFieldOffset(bufio.NewScanner(f), "child_pid")
		f.Close()
		if ok {
			return off
		}
	}
	return defaultForkChildOff
}

// parseFieldOffset finds "field:pid_t child_pid;	offset:44;	size:4;".
func parseFieldOffset(sc *bufio.Scanner, field string) (int16, bool) {
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		decl, rest, ok := strings.Cut(l, ";")
		if !ok || !strings.HasPrefix(decl, "field:") {
			continue
		}
		f := strings.Fields(decl)
		if len(f) == 0 || f[len(f)-1] != field {
			continue
		}
		for _, part := range strings.Split(rest, ";") {
			v, ok := strings.CutPrefix(strings.TrimSpace(part), "offset:")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 8 || n > 512 || n%4 != 0 {
				return 0, false
			}
			return int16(n), true
		}
	}
	return 0, false
}

// Stack layout used by the programs (offsets from the frame pointer).
const (
	fpComm  = -16 // comm[16]
	fpKey   = -20 // u32 tgid
	fpKey2  = -24 // u32 origin / child pid
	fpStat  = -28 // u32 stats index
	fpState = -48 // stateVal (16, 8-aligned)
	fpProc  = -64 // procVal (16, 8-aligned)
)

// execInsns: the exec'd process's comm has an entry -> new state, own origin.
// Without one, an inherited state stays (the process is still the same
// "member" of its parent's rule, as it would stay in its parent's cgroup).
func execInsns(fd fds) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, fpComm),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
		asm.LoadMapPtr(asm.R1, fd.names),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpComm),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R6, asm.R0, 0, asm.Word), // mark
		asm.LoadMem(asm.R7, asm.R0, 4, asm.Word), // kind
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, fpKey, asm.R0, asm.Word),
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R8, asm.R0), // gen
		asm.StoreMem(asm.RFP, fpState, asm.R6, asm.Word),
		asm.StoreMem(asm.RFP, fpState+4, asm.R7, asm.Word),
		asm.StoreMem(asm.RFP, fpState+8, asm.R8, asm.DWord),
		asm.LoadMapPtr(asm.R1, fd.state),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, fpState),
		asm.Mov.Imm(asm.R4, 0), // BPF_ANY
		asm.FnMapUpdateElem.Call(),
		asm.LoadMem(asm.R1, asm.RFP, fpKey, asm.Word),
		asm.StoreMem(asm.RFP, fpProc, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, fpProc+4, 0, asm.Word),
		asm.StoreMem(asm.RFP, fpProc+8, asm.R8, asm.DWord),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, fpProc),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}
}

// forkInsns: the child (process or thread) inherits the parent's entry.
func forkInsns(fd fds, childOff int16) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), // tracepoint record
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, fpKey, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		// copy the value: a map value pointer must not be handed back to
		// an update of the same LRU map
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.StoreMem(asm.RFP, fpProc, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.StoreMem(asm.RFP, fpProc+8, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R6, childOff, asm.Word),
		asm.StoreMem(asm.RFP, fpKey2, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey2),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, fpProc),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}
}

// forkRawInsns is forkInsns for a raw tracepoint: ctx is u64 args[]
// (parent, child task_struct pointers), the child's pid is read with
// bpf_probe_read_kernel.
func forkRawInsns(fd fds, pidOff int32) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 8, asm.DWord), // args[1]: child
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, fpKey, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.StoreMem(asm.RFP, fpProc, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.StoreMem(asm.RFP, fpProc+8, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, fpKey2),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R6),
		asm.Add.Imm(asm.R3, pidOff),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "out"),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey2),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, fpProc),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}
}

// exitInsns: forget the exiting task (thread id; the main thread's id is
// the tgid). States stay until the LRU drops them: inherited entries of
// children still point to them.
func exitInsns(fd fds) asm.Instructions {
	return asm.Instructions{
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, fpKey, asm.R0, asm.Word), // low 32 bits: tid
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
}

// count adds 1 to stats[i]. entry (if set) names its first instruction,
// label its end (unique per use).
func count(fd fds, i int, entry, label string) asm.Instructions {
	first := asm.StoreImm(asm.RFP, fpStat, int64(i), asm.Word)
	if entry != "" {
		first = first.WithSymbol(entry)
	}
	return asm.Instructions{
		first,
		asm.LoadMapPtr(asm.R1, fd.stats),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpStat),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, label),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label), // jump target
	}
}

// sockInsns: decide on a new socket. Returns 1 (allow) or 0 (EPERM).
func sockInsns(fd fds, level int32, id uint64, holdNs uint64) asm.Instructions {
	var in asm.Instructions
	add := func(i ...asm.Instruction) { in = append(in, i...) }
	add(
		asm.Mov.Reg(asm.R6, asm.R1), // ctx (struct bpf_sock)
		asm.Mov.Imm(asm.R1, level),
		asm.FnGetCurrentAncestorCgroupId.Call(),
		asm.LoadImm(asm.R2, int64(id), asm.DWord),
		asm.JEq.Reg(asm.R0, asm.R2, "allow"), // in shuntd's tree: rules decide
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, fpKey, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd.procs),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "comm"),            // older than the guard
		asm.LoadMem(asm.R7, asm.R0, 8, asm.DWord), // gen
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),  // origin
		asm.StoreMem(asm.RFP, fpKey2, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, fd.state),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpKey2),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"), // released (watcher decided)
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.JNE.Reg(asm.R1, asm.R7, "allow"), // pid reused: not ours
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMem(asm.R1, asm.R8, 4, asm.Word),
		asm.JEq.Imm(asm.R1, KindMark, "mark"),
		asm.JNE.Imm(asm.R1, KindHold, "allow"),
		// held: refuse until HoldMax after the exec
		asm.FnKtimeGetNs.Call(),
		asm.LoadMem(asm.R1, asm.R8, 8, asm.DWord),
		asm.Sub.Reg(asm.R0, asm.R1),
		asm.LoadImm(asm.R1, int64(holdNs), asm.DWord),
		asm.JGT.Reg(asm.R0, asm.R1, "expired"),
	)
	add(count(fd, StatHeld, "", "c_held")...)
	add(
		asm.Mov.Imm(asm.R0, 0), // EPERM
		asm.Return(),
	)
	add(count(fd, StatExpired, "expired", "c_exp")...)
	add(asm.Ja.Label("allow"))
	add(
		asm.LoadMem(asm.R1, asm.R8, 0, asm.Word).WithSymbol("mark"),
		asm.StoreMem(asm.R6, sockMarkOff, asm.R1, asm.Word),
	)
	add(count(fd, StatMarked, "", "c_mark")...)
	add(asm.Ja.Label("allow"))
	// comm table: only marks (a held name's process was already decided
	// by the watcher's scan when the guard was loaded)
	add(
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("comm"),
		asm.Add.Imm(asm.R1, fpComm),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
		asm.LoadMapPtr(asm.R1, fd.names),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, fpComm),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word),
		asm.JNE.Imm(asm.R1, KindMark, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.R6, sockMarkOff, asm.R1, asm.Word),
	)
	add(count(fd, StatComm, "", "c_comm")...)
	add(
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return in
}

// key is comm as the kernel stores it: 16 bytes, NUL padded.
func key(name string) (k [16]byte) {
	copy(k[:15], name)
	return k
}

// SetEntries replaces the name table. When it changed, all process states
// are forgotten (they were made for the old rules); an unchanged table (the
// daemon applies the plan again on every network change) keeps them.
func (g *Guard) SetEntries(entries map[string]Entry) error {
	if len(entries) > MaxNames {
		return fmt.Errorf("%d app names, at most %d", len(entries), MaxNames)
	}
	var old [][16]byte
	have := map[[16]byte]nameVal{}
	var k [16]byte
	var v nameVal
	it := g.m.names.Iterate()
	for it.Next(&k, &v) {
		old = append(old, k)
		have[k] = v
	}
	want := map[[16]byte]nameVal{}
	for n, e := range entries {
		want[key(n)] = e.value()
	}
	if maps.Equal(have, want) {
		return nil
	}
	for k, v := range want {
		if err := g.m.names.Put(k, v); err != nil {
			return err
		}
	}
	for _, k := range old {
		if _, keep := want[k]; !keep {
			if err := g.m.names.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
		}
	}
	return clearMap(g.m.state)
}

func clearMap(m *ebpf.Map) error {
	var keys []uint32
	var k uint32
	var v stateVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// Release ends the hold of pid once the watcher has decided on it (moved,
// or no rule matched). since is the monotonic time (ns) the watcher began
// to look: a hold from a later exec stays. Marks stay too: children made
// before the move keep their rule's route.
func (g *Guard) Release(pid int, since int64) {
	k := uint32(pid)
	var v stateVal
	if err := g.m.state.Lookup(k, &v); err != nil {
		return
	}
	if v.Kind == KindHold && int64(v.Gen) <= since {
		g.m.state.Delete(k)
	}
}

// Stats returns the counters (see StatMarked …).
func (g *Guard) Stats() (s [numStats]uint64) {
	for i := range s {
		g.m.stats.Lookup(uint32(i), &s[i])
	}
	return s
}

// Now is the clock the programs use (bpf_ktime_get_ns), in ns.
func Now() int64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return ts.Nano()
}

// Close detaches the programs.
func (g *Guard) Close() error {
	var errs []error
	for i := len(g.links) - 1; i >= 0; i-- {
		errs = append(errs, g.links[i].Close())
	}
	for _, p := range g.progs {
		errs = append(errs, p.Close())
	}
	for _, m := range []*ebpf.Map{g.m.names, g.m.procs, g.m.state, g.m.stats} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}
