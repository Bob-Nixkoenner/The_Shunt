//go:build windows

package wfp

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The boot-time copies alternate between two key sets, so a refresh never
// deletes and adds the same key in one transaction (BFE then leaves the
// filter out of the boot-time policy, see genKey).
func TestBootGenAlternates(t *testing.T) {
	for _, base := range []windows.GUID{bootFilterBase, quBootBase} {
		live := map[windows.GUID]bool{}
		del := func(k *windows.GUID) bool { ok := live[*k]; delete(live, *k); return ok }
		prev := map[windows.GUID]bool{}
		for round := 0; round < 4; round++ {
			gen := nextGen(del, base, 8)
			if want := uint8(round % 2); gen != want {
				t.Fatalf("round %d: generation %d, want %d", round, gen, want)
			}
			next := map[windows.GUID]bool{}
			for i := uint32(0); i < 8; i++ {
				k := genKey(base, gen, i)
				if prev[k] {
					t.Fatalf("round %d: key %v deleted and added in one refresh", round, k)
				}
				next[k], live[k] = true, true
			}
			if len(live) != 8 {
				t.Fatalf("round %d: %d live keys, want 8 (old set not deleted)", round, len(live))
			}
			prev = next
		}
	}
}

// No key of one set may fall into another: kill switch persistent and boot
// (both generations), quiet persistent and boot (both generations).
func TestFilterKeysDisjoint(t *testing.T) {
	seen := map[windows.GUID]string{}
	add := func(name string, k windows.GUID) {
		if o, ok := seen[k]; ok {
			t.Fatalf("key %v in %s and %s", k, o, name)
		}
		seen[k] = name
	}
	for i := uint32(0); i < maxFilters; i++ {
		add("ks", filterKey(i))
		add("ks boot 0", genKey(bootFilterBase, 0, i))
		add("ks boot 1", genKey(bootFilterBase, 1, i))
	}
	for i := uint32(0); i < quMaxFilters; i++ {
		k := quBase
		k.Data1 += i
		add("quiet", k)
		add("quiet boot 0", genKey(quBootBase, 0, i))
		add("quiet boot 1", genKey(quBootBase, 1, i))
	}
	for _, k := range []windows.GUID{providerKey, sublayerKey, quProvider, quSublayer} {
		add("object", k)
	}
}
