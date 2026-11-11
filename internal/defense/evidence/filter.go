package evidence

import (
	"golang.org/x/net/bpf"
)

// What may be captured, and nothing else:
//
//	(a) unsolicited inbound traffic: the first packet of a new inbound
//	    connection (conntrack "new", from the NFLOG group of the defense
//	    table) to a decoy port or a port nothing listens on;
//	(b) link-layer control frames: ARP, DHCPv4 (UDP port 67/68), ICMPv6
//	    router/neighbour discovery (types 133-136) and DHCPv6 (546/547),
//	    incoming only;
//	(c) the Shunt's own DNS/TLS probe packets are NOT captured: they cannot
//	    be told apart from normal traffic by a packet filter without
//	    tracking sockets, and "never normal traffic" wins.
//
// Normal outgoing and established traffic is never captured.

// InboundWanted decides (a) for the first packet of a new inbound
// connection: yes for a decoy port, yes for a port nothing listens on, no
// for a port a real program listens on (that is a service in use, not an
// attack).
func InboundWanted(proto string, port int, decoys []int, listening func(proto string, port int) bool) bool {
	if proto == "tcp" {
		for _, d := range decoys {
			if d == port {
				return true
			}
		}
	}
	return listening == nil || !listening(proto, port)
}

type asm struct {
	ins   []bpf.Instruction
	label map[string]int
	jumps []jump
}

type jump struct {
	at   int
	t, f string
	cond bpf.JumpTest
	val  uint32
}

func (a *asm) emit(i bpf.Instruction) { a.ins = append(a.ins, i) }
func (a *asm) mark(l string)          { a.label[l] = len(a.ins) }

// jif emits a conditional jump to labels (""  = fall through).
func (a *asm) jif(c bpf.JumpTest, v uint32, t, f string) {
	a.jumps = append(a.jumps, jump{len(a.ins), t, f, c, v})
	a.ins = append(a.ins, nil)
}

func (a *asm) resolve() []bpf.Instruction {
	for _, j := range a.jumps {
		skip := func(l string) uint8 {
			if l == "" {
				return 0
			}
			return uint8(a.label[l] - j.at - 1)
		}
		a.ins[j.at] = bpf.JumpIf{Cond: j.cond, Val: j.val, SkipTrue: skip(j.t), SkipFalse: skip(j.f)}
	}
	return a.ins
}

// ControlFilter is the classic BPF program for (b), for Ethernet frames
// without a VLAN tag (tagged frames are not captured).
func ControlFilter() []bpf.Instruction {
	a := &asm{label: map[string]int{}}
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jif(bpf.JumpEqual, 0x0806, "accept", "")
	a.jif(bpf.JumpEqual, 0x0800, "v4", "")
	a.jif(bpf.JumpEqual, 0x86dd, "v6", "drop")
	a.mark("v4")
	a.emit(bpf.LoadAbsolute{Off: 23, Size: 1})
	a.jif(bpf.JumpEqual, 17, "", "drop")
	a.emit(bpf.LoadAbsolute{Off: 20, Size: 2}) // flags + fragment offset
	a.jif(bpf.JumpBitsSet, 0x1fff, "drop", "")
	a.emit(bpf.LoadMemShift{Off: 14})
	a.emit(bpf.LoadIndirect{Off: 16, Size: 2}) // UDP destination port
	a.jif(bpf.JumpEqual, 67, "accept", "")
	a.jif(bpf.JumpEqual, 68, "accept", "drop")
	a.mark("v6")
	a.emit(bpf.LoadAbsolute{Off: 20, Size: 1}) // next header
	a.jif(bpf.JumpEqual, 58, "icmp6", "")
	a.jif(bpf.JumpEqual, 17, "udp6", "drop")
	a.mark("icmp6")
	a.emit(bpf.LoadAbsolute{Off: 54, Size: 1}) // ICMPv6 type
	a.jif(bpf.JumpLessThan, 133, "drop", "")
	a.jif(bpf.JumpGreaterThan, 136, "drop", "accept")
	a.mark("udp6")
	a.emit(bpf.LoadAbsolute{Off: 56, Size: 2}) // UDP destination port
	a.jif(bpf.JumpEqual, 546, "accept", "")
	a.jif(bpf.JumpEqual, 547, "accept", "drop")
	a.mark("accept")
	a.emit(bpf.RetConstant{Val: 262144})
	a.mark("drop")
	a.emit(bpf.RetConstant{Val: 0})
	return a.resolve()
}

// ControlFilterRaw is ControlFilter assembled for the kernel.
func ControlFilterRaw() ([]bpf.RawInstruction, error) { return bpf.Assemble(ControlFilter()) }
