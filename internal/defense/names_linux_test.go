package defense

import (
	"testing"

	"golang.org/x/net/bpf"
)

// the BPF program lets the name ports through and nothing else
func TestNamesFilterProgram(t *testing.T) {
	raw := make([]bpf.RawInstruction, len(namesFilter))
	for i, f := range namesFilter {
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
	pass := func(p []byte) bool {
		n, err := vm.Run(p)
		return err == nil && n > 0
	}
	for _, c := range []struct {
		sp, dp uint16
		want   bool
	}{{68, 67, true}, {67, 68, true}, {5353, 5353, true}, {40000, 5353, true}, {5355, 40000, true}, {40000, 5355, true}, {1234, 80, false}, {53, 53, false}} {
		if got := pass(udp4("192.0.2.3", c.sp, c.dp, []byte("x"))); got != c.want {
			t.Errorf("%d->%d: %v", c.sp, c.dp, got)
		}
	}
	tcp := udp4("192.0.2.3", 5353, 5353, nil)
	tcp[9] = 6
	if pass(tcp) {
		t.Error("tcp passed")
	}
	frag := udp4("192.0.2.3", 5353, 5353, nil)
	frag[6] = 0x00
	frag[7] = 0x08
	if pass(frag) {
		t.Error("fragment passed")
	}
}
