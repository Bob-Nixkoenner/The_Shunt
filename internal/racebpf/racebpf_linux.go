// Package racebpf closes the start race of app rules: between a program's
// exec and the moment the app watcher has moved it into its rule's cgroup,
// its sockets would take the default route (lab tests A02/A06/A07).
//
// A small eBPF program on the root cgroup runs when any socket is created
// (cgroup/sock_create). If the process is not inside shuntd's cgroup tree
// yet and its name (comm) has a start mark, the socket gets that route mark.
// The nftables classification keeps a Shunt mark that is already set (see
// nft.Render, route_out), so the first DNS query and the first connection
// take the rule's route, DNS proxy and kill switch included. Once the
// program is in its group, new sockets are unmarked and all rules apply as
// usual (a domain rule before the app rule, for example).
//
// The program is written with cilium/ebpf's assembler, so building needs no
// clang. It is detached when shuntd exits (its link dies with the process).
// Without eBPF (old kernel, missing capability) shuntd works as before.
package racebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// MaxNames is the size of the name map.
const MaxNames = 1024

// offset of mark in struct bpf_sock (bound_dev_if, family, type, protocol, mark)
const sockMarkOff = 16

// Guard is the loaded and attached program.
type Guard struct {
	names *ebpf.Map
	prog  *ebpf.Program
	link  link.Link
}

// Start loads the program and attaches it to the cgroup2 mount. root is
// shuntd's cgroup (relative to mount): processes below it are left alone.
func Start(mount, root string) (*Guard, error) {
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
	if strings.Trim(root, "/") == "" {
		return nil, errors.New("shuntd runs in the root cgroup")
	}
	names, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "shunt_start", Type: ebpf.Hash, KeySize: 16, ValueSize: 4, MaxEntries: MaxNames,
	})
	if err != nil {
		return nil, fmt.Errorf("map: %w", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "shunt_start",
		Type:         ebpf.CGroupSock,
		AttachType:   ebpf.AttachCGroupInetSockCreate,
		License:      "Apache-2.0",
		Instructions: instructions(names.FD(), level, id),
	})
	if err != nil {
		names.Close()
		return nil, fmt.Errorf("program: %w", err)
	}
	l, err := link.AttachCgroup(link.CgroupOptions{Path: mount, Attach: ebpf.AttachCGroupInetSockCreate, Program: prog})
	if err != nil {
		prog.Close()
		names.Close()
		return nil, fmt.Errorf("attach: %w", err)
	}
	return &Guard{names: names, prog: prog, link: l}, nil
}

// instructions: if the task is not below cgroup id (at level), look up its
// comm in the name map and set the socket's mark. Always allows the socket.
func instructions(mapFD int, level int32, id uint64) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), // ctx (struct bpf_sock)
		asm.Mov.Imm(asm.R1, level),
		asm.FnGetCurrentAncestorCgroupId.Call(),
		asm.LoadImm(asm.R2, int64(id), asm.DWord),
		asm.JEq.Reg(asm.R0, asm.R2, "out"), // already in shuntd's tree: rules decide
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.R6, sockMarkOff, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("out"), // 1 = allow
		asm.Return(),
	}
}

// key is comm as the kernel stores it: 16 bytes, NUL padded.
func key(name string) (k [16]byte) {
	copy(k[:15], name)
	return k
}

// SetMarks replaces the name -> route mark table.
func (g *Guard) SetMarks(marks map[string]uint32) error {
	if len(marks) > MaxNames {
		return fmt.Errorf("%d app names, at most %d", len(marks), MaxNames)
	}
	var old [][16]byte
	var k [16]byte
	var v uint32
	it := g.names.Iterate()
	for it.Next(&k, &v) {
		old = append(old, k)
	}
	for n, m := range marks {
		if err := g.names.Put(key(n), m); err != nil {
			return err
		}
	}
	for _, k := range old {
		n := strings.TrimRight(string(k[:]), "\x00")
		if _, keep := marks[n]; !keep {
			if err := g.names.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
		}
	}
	return nil
}

// Close detaches the program.
func (g *Guard) Close() error {
	return errors.Join(g.link.Close(), g.prog.Close(), g.names.Close())
}
