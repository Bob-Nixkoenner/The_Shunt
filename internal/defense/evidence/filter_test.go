package evidence

import (
	"testing"

	"golang.org/x/net/bpf"
)

func eth(t uint16) []byte {
	return append(make([]byte, 12), byte(t>>8), byte(t))
}

func ip4udp(dport uint16, ihl int, frag uint16, proto byte) []byte {
	p := eth(0x0800)
	h := make([]byte, ihl*4)
	h[0] = 0x40 | byte(ihl)
	h[6], h[7] = byte(frag>>8), byte(frag)
	h[9] = proto
	p = append(p, h...)
	u := []byte{0, 68, byte(dport >> 8), byte(dport), 0, 8, 0, 0}
	return append(p, u...)
}

func ip6(next byte, payload []byte) []byte {
	p := eth(0x86dd)
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = next
	return append(append(p, h...), payload...)
}

func TestControlFilter(t *testing.T) {
	vm, err := bpf.NewVM(ControlFilter())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ControlFilterRaw(); err != nil {
		t.Fatal(err)
	}
	icmp := func(typ byte) []byte { return ip6(58, []byte{typ, 0, 0, 0}) }
	udp6 := func(dport uint16) []byte { return ip6(17, []byte{0, 1, byte(dport >> 8), byte(dport), 0, 8, 0, 0}) }
	tcp4 := ip4udp(80, 5, 0, 6)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"ARP", append(eth(0x0806), make([]byte, 28)...), true},
		{"DHCPv4 to server port", ip4udp(67, 5, 0, 17), true},
		{"DHCPv4 to client port", ip4udp(68, 5, 0, 17), true},
		{"DHCPv4 with IP options (ihl 6)", ip4udp(67, 6, 0, 17), true},
		{"UDP to 53 (normal traffic)", ip4udp(53, 5, 0, 17), false},
		{"UDP 443 (QUIC)", ip4udp(443, 5, 0, 17), false},
		{"TCP to 67 is not DHCP", ip4udp(67, 5, 0, 6), false},
		{"fragment, not the first", ip4udp(67, 5, 0x0010, 17), false},
		{"RS", icmp(133), true}, {"RA", icmp(134), true}, {"NS", icmp(135), true}, {"NA", icmp(136), true},
		{"echo request", icmp(128), false}, {"redirect", icmp(137), false},
		{"DHCPv6 server", udp6(547), true}, {"DHCPv6 client", udp6(546), true},
		{"UDPv6 443", udp6(443), false},
		{"TCP over IPv6", ip6(6, make([]byte, 20)), false},
		{"TCP over IPv4", tcp4, false},
		{"other ethertype", eth(0x88cc), false},
	}
	for _, c := range cases {
		out, err := vm.Run(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (out > 0) != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, out > 0, c.want)
		}
	}
}

func TestInboundWanted(t *testing.T) {
	listening := func(proto string, port int) bool { return proto == "tcp" && port == 8080 }
	if !InboundWanted("tcp", 22, []int{22, 2222}, listening) {
		t.Fatal("decoy port must be wanted")
	}
	if !InboundWanted("tcp", 3389, nil, listening) || !InboundWanted("udp", 5060, nil, listening) {
		t.Fatal("closed ports must be wanted")
	}
	if InboundWanted("tcp", 8080, []int{22}, listening) {
		t.Fatal("a real service's traffic is not captured")
	}
	if !InboundWanted("udp", 22, []int{22}, listening) {
		t.Fatal("udp to a closed port is unsolicited")
	}
}
