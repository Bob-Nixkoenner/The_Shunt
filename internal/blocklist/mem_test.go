package blocklist

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// synth builds a list text with n distinct names (half "||name^", half
// hosts lines). Names are made up and resolve nowhere.
func synth(n int) []byte {
	var b bytes.Buffer
	b.Grow(n * 32)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			fmt.Fprintf(&b, "||n%d.zone%d.invalid^\n", i, i%997)
		} else {
			fmt.Fprintf(&b, "0.0.0.0 h%d.zone%d.invalid\n", i, i%997)
		}
	}
	return b.Bytes()
}

func heapInuse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// TestListMemory: 5 million names must stay far below what a Go map of
// strings needs (about 100 bytes per name).
func TestListMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a large list")
	}
	const n = 5_000_000
	data := synth(n)
	before := heapInuse()
	l, err := Parse("big", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	after := heapInuse()
	if l.Len() != n {
		t.Fatalf("Len = %d, want %d", l.Len(), n)
	}
	per := float64(after-before) / n
	t.Logf("%d names: heap +%.1f MB, %.1f B/name", n, float64(after-before)/1e6, per)
	if per > 16 {
		t.Errorf("%.1f B per name, want at most 16", per)
	}
	if !l.Has("n0.zone0.invalid") || !l.Has("sub.n2.zone2.invalid") || l.Has("sub.h1.zone1.invalid") || !l.Has("h1.zone1.invalid") {
		t.Error("lookups wrong after load")
	}
	runtime.KeepAlive(data)
}

func BenchmarkHas(b *testing.B) {
	const n = 1_000_000
	l, err := Parse("big", bytes.NewReader(synth(n)))
	if err != nil {
		b.Fatal(err)
	}
	// typical query: a few labels, mostly not listed; every 8th is a
	// subdomain of a listed name
	q := make([]string, 1024)
	for i := range q {
		if i%8 == 0 {
			q[i] = fmt.Sprintf("cdn.n%d.zone%d.invalid", i*2, (i*2)%997)
		} else {
			q[i] = fmt.Sprintf("www.static%d.example-site.test", i)
		}
	}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		l.Has(q[i&1023])
	}
}

func BenchmarkParse(b *testing.B) {
	data := synth(1_000_000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse("big", bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// Duplicates count once; "with subdomains" wins in either order; the
// index works for every list size, also a single entry.
func TestHashedListEdges(t *testing.T) {
	for _, txt := range []string{
		"0.0.0.0 a.invalid\n||a.invalid^\nb.invalid\nb.invalid\n",
		"||a.invalid^\n0.0.0.0 a.invalid\nb.invalid\n0.0.0.0 b.invalid\n",
	} {
		l, err := Parse("d", bytes.NewReader([]byte(txt)))
		if err != nil {
			t.Fatal(err)
		}
		if l.Len() != 2 {
			t.Errorf("Len = %d, want 2", l.Len())
		}
		if !l.Has("x.a.invalid") || l.Has("x.b.invalid") || !l.Has("b.invalid") || l.Has("invalid") {
			t.Errorf("wrong lookups for %q", txt)
		}
	}
	for _, n := range []int{1, 2, 7, 8, 9, 63, 1000, 100_001} {
		l, err := Parse("s", bytes.NewReader(synth(n)))
		if err != nil {
			t.Fatal(err)
		}
		if l.Len() != n {
			t.Fatalf("n=%d: Len = %d", n, l.Len())
		}
		for i := 0; i < n; i++ {
			var name string
			if i%2 == 0 {
				name = fmt.Sprintf("deep.n%d.zone%d.invalid", i, i%997)
			} else {
				name = fmt.Sprintf("h%d.zone%d.invalid", i, i%997)
			}
			if !l.Has(name) {
				t.Fatalf("n=%d: %s not found", n, name)
			}
		}
		if l.Has(fmt.Sprintf("n%d.zone0.invalid", n+1)) {
			t.Fatalf("n=%d: false hit", n)
		}
	}
}
