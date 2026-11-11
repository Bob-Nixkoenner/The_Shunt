package defense

import (
	"testing"

	"golang.org/x/net/bpf"
)

// The kernel filter is run in user space (no root needed).
func TestRAFilterProgram(t *testing.T) {
	raw := make([]bpf.RawInstruction, len(raFilter))
	for i, f := range raFilter {
		raw[i] = bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}
	}
	ins, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("disassemble")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	run := func(p []byte) bool {
		n, err := vm.Run(p)
		if err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	if !run(v6(ll(1), 255, 58, raBody(1800))) {
		t.Fatal("RA must pass")
	}
	if run(v6(ll(1), 255, 58, []byte{135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})) {
		t.Fatal("neighbour solicitation must not pass")
	}
	if !run(v6(ll(1), 255, 44, append([]byte{58, 0, 0, 0, 0, 0, 0, 1}, raBody(1800)...))) {
		t.Fatal("fragment must pass")
	}
	if !run(dhcp6(ll(1), 2, 1, 2)) {
		t.Fatal("DHCPv6 reply must pass")
	}
	u := dhcp6(ll(1), 2, 1, 2)
	u[41] = 0x01 // other source port
	if run(u) {
		t.Fatal("other UDP must not pass")
	}
	if run(v6(ll(1), 255, 6, make([]byte, 24))) {
		t.Fatal("TCP must not pass")
	}
}
