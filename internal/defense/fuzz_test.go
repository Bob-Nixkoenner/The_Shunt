package defense

import (
	"bytes"
	"testing"
)

// Fuzz targets for every parser that reads bytes from strangers. Each must
// never panic and must keep its own output limits.

func FuzzParseDHCPv6(f *testing.F) {
	ip6 := make([]byte, 40)
	ip6[0], ip6[6], ip6[7] = 0x60, 17, 255
	udp := []byte{0x02, 0x23, 0x02, 0x22, 0, 20, 0, 0}
	f.Add(append(append(append([]byte{}, ip6...), udp...), 2, 0, 0, 1, 0, 2, 0, 4, 1, 2, 3, 4))
	f.Add(append(append([]byte{}, ip6...), udp...))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ok := ParseDHCPv6(b)
		if ok && len(r.DUID) > 260 {
			t.Fatalf("duid %d", len(r.DUID))
		}
	})
}

func FuzzParseClassless(f *testing.F) {
	f.Add([]byte{0, 192, 0, 2, 1})
	f.Add([]byte{1, 0, 192, 0, 2, 1, 1, 128, 192, 0, 2, 1})
	f.Add([]byte{24, 198, 51, 100, 192, 0, 2, 1})
	f.Add([]byte{33})
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, _ := parseClassless(b)
		if len(rs) > maxDHCPRoutes {
			t.Fatalf("%d routes", len(rs))
		}
		for _, r := range rs {
			if r.Prefix.Bits() < 0 || r.Prefix.Bits() > 32 {
				t.Fatalf("%v", r.Prefix)
			}
		}
	})
}

func FuzzParseDHCPReply(f *testing.F) {
	p := make([]byte, 240)
	p[0], p[236], p[237], p[238], p[239] = 2, 0x63, 0x82, 0x53, 0x63
	f.Add(append(append([]byte{}, p...), 53, 1, 2, 54, 4, 192, 0, 2, 1, 255))
	f.Add(append(append([]byte{}, p...), 53, 1, 5, 54, 200))
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, ok := ParseDHCPReply(b); ok && !a.Is4() {
			t.Fatalf("%v", a)
		}
	})
}

func FuzzParseLoggedPacket(f *testing.F) {
	v4 := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 5, 192, 0, 2, 2, 0x30, 0x39, 0, 22}
	f.Add(v4)
	f.Add([]byte{0x4f, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8})
	v6 := make([]byte, 48)
	v6[0], v6[6] = 0x60, 6
	f.Add(v6)
	f.Fuzz(func(t *testing.T, b []byte) {
		if src, proto, port, ok := ParseLoggedPacket(b); ok && (!src.IsValid() || port < 0 || port > 65535 || (proto != "tcp" && proto != "udp")) {
			t.Fatalf("%v %s %d", src, proto, port)
		}
		if s, d, ok := ParseConnPacket(b); ok && (!s.IsValid() || !d.IsValid()) {
			t.Fatalf("%v %v", s, d)
		}
	})
}

func FuzzParseLists(f *testing.F) {
	f.Add([]byte(exampleList))
	f.Add([]byte("192.0.2.0/24\n# c\n2001:db8::/32,x\n\"198.51.100.1\";y\n"))
	f.Add([]byte("0123456789abcdef0123456789ABCDEF,mal\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range ParseList(bytes.NewReader(b)) {
			if !p.IsValid() || p != p.Masked() {
				t.Fatalf("%v", p)
			}
		}
		for k := range ParseJA3List(bytes.NewReader(b)) {
			if len(k) != 32 {
				t.Fatalf("%q", k)
			}
		}
	})
}

// cleanName output goes into logs and the UI: printable ASCII, 32 at most.
func FuzzCleanName(f *testing.F) {
	f.Add("root")
	f.Add("a\x1b[31mred\r\n<script>‮")
	f.Fuzz(func(t *testing.T, s string) {
		c := cleanName(s)
		if len(c) > 32 {
			t.Fatalf("len %d", len(c))
		}
		for i := 0; i < len(c); i++ {
			if c[i] < 0x20 || c[i] >= 0x7f {
				t.Fatalf("byte %x", c[i])
			}
		}
	})
}
