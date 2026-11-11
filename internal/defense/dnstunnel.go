package defense

import (
	"math"
	"strings"
)

// DNSQuery is one observed lookup.
type DNSQuery struct {
	Name string
	Type string // "A", "TXT", ...
}

// shannon returns the bits of entropy per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	cnt := map[rune]int{}
	n := 0
	for _, r := range s {
		cnt[r]++
		n++
	}
	var h float64
	for _, c := range cnt {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func clamp01(x float64) float64 { return math.Max(0, math.Min(1, x)) }

// DNSTunnelScore rates a batch of queries from one client: 0 (normal) to 1
// (looks like tunnelling). It uses the length and entropy of the leftmost
// label and the share of TXT queries; fewer than 5 queries score 0.
func DNSTunnelScore(qs []DNSQuery) float64 {
	if len(qs) < 5 {
		return 0
	}
	var length, ent float64
	txt := 0
	for _, q := range qs {
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		label, _, _ := strings.Cut(name, ".")
		length += float64(len(label))
		ent += shannon(label)
		if strings.EqualFold(q.Type, "TXT") {
			txt++
		}
	}
	n := float64(len(qs))
	ls := clamp01((length/n - 20) / 30)
	es := clamp01((ent/n - 3.0) / 1.5)
	ts := float64(txt) / n
	return 0.4*ls + 0.4*es + 0.2*ts
}
