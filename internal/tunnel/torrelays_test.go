package tunnel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTorRelays(t *testing.T) {
	d := t.TempDir()
	if _, err := TorRelays(d); err == nil {
		t.Error("no consensus: want error")
	}
	cons := "network-status-version 3 microdesc\n" +
		"r A id dig 2026-10-30 10:00:00 192.0.2.1 9001 0\n" +
		"a [2001:db8::1]:9001\n" +
		"s Fast Guard\n" +
		"r B id dig 2026-10-30 10:00:00 198.51.100.7 443 0\n" +
		"r C id dig 2026-10-30 10:00:00 192.0.2.1 9002 0\n" +
		"r D id 2026-10-30 10:00:00 203.0.113.4 9001 0\n" + // real microdesc format: no digest
		"r broken\n"
	if err := os.WriteFile(filepath.Join(d, "cached-microdesc-consensus"), []byte(cons), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := TorRelays(d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1/32", "198.51.100.7/32", "2001:db8::1/128", "203.0.113.4/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: got %v want %v", i, got[i], want[i])
		}
	}
}

func TestBridgeDsts(t *testing.T) {
	dst, opaque := BridgeDsts([]string{
		"obfs4 192.0.2.5:443 FP cert=x iat-mode=0",
		"Bridge 198.51.100.9:9001 FP",
		"obfs4 [2001:db8::5]:443 FP cert=x",
		"obfs4 nonsense FP",
	})
	if opaque || len(dst) != 3 {
		t.Fatalf("got %v opaque=%v", dst, opaque)
	}
	for _, b := range []string{"snowflake 192.0.2.3:80 FP", "meek_lite 192.0.2.2:80 FP url=x", "webtunnel [2001:db8::1]:443 FP url=x"} {
		if _, op := BridgeDsts([]string{b}); !op {
			t.Errorf("%q should be opaque", b)
		}
	}
}
