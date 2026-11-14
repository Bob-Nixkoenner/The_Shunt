package dnsproxy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// L-13: dns.direct = "system" skips resolved's DNS-over-TLS and DNSSEC; the
// daemon warns when they are set. Drop-ins override resolved.conf.
func TestResolvedProtections(t *testing.T) {
	dir := t.TempDir()
	oldConf, oldDirs := resolvedConf, resolvedConfDirs
	defer func() { resolvedConf, resolvedConfDirs = oldConf, oldDirs }()
	resolvedConf = filepath.Join(dir, "resolved.conf")
	etc := filepath.Join(dir, "etc.d")
	resolvedConfDirs = []string{filepath.Join(dir, "usr.d"), etc}

	if got := ResolvedProtections(); len(got) != 0 {
		t.Fatalf("no files: %v", got)
	}
	write := func(p, s string) {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(resolvedConf, "[Resolve]\n#DNSOverTLS=yes\nDNSSEC=allow-downgrade\n[Other]\nDNSOverTLS=yes\n")
	if got := ResolvedProtections(); !slices.Equal(got, []string{"DNSSEC=allow-downgrade"}) {
		t.Fatalf("resolved.conf: %v", got)
	}
	write(filepath.Join(etc, "50-dot.conf"), "[Resolve]\nDNSOverTLS=opportunistic\nDNSSEC=no\n")
	if got := ResolvedProtections(); !slices.Equal(got, []string{"DNSOverTLS=opportunistic"}) {
		t.Fatalf("drop-in: %v", got)
	}
}
