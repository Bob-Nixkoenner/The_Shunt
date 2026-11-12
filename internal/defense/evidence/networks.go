package evidence

import (
	"sort"
	"strings"
)

// UnknownNet is the label of log lines that cannot be tied to a network (they
// come before the first "network joined" line of the log, or from an older
// version that did not label networks).
const UnknownNet = "unknown"

// DetailField returns the value of key in a "k=v k=v" detail ("" if absent).
func DetailField(detail, key string) string {
	for _, f := range strings.Fields(detail) {
		if k, v, ok := strings.Cut(f, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// NetInfo is one network as the log knows it: only a short label and class,
// never a name. Label is the same for every visit to the same network.
type NetInfo struct {
	ID      string         `json:"id"`
	Class   string         `json:"class"`
	Visits  int            `json:"visits"`
	First   string         `json:"first_utc"`
	Last    string         `json:"last_utc"`
	Lines   int            `json:"lines"`
	Sources int            `json:"sources"`
	Kinds   map[string]int `json:"kinds,omitempty"`
}

// netMarker reports whether e says "the network is now X" and which.
func netMarker(e Entry) (id string, ok bool) {
	if e.Kind != "net_enter" && e.Kind != "state_net" {
		return "", false
	}
	id = DetailField(e.Detail, "net")
	if id == "" {
		id = UnknownNet
	}
	return id, true
}

// labelNets returns the network label of every entry (same order). A line
// belongs to the network named by the last marker before it.
func labelNets(es []Entry) []string {
	out := make([]string, len(es))
	cur := UnknownNet
	for i, e := range es {
		if id, ok := netMarker(e); ok {
			cur = id
		}
		out[i] = cur
	}
	return out
}

// Networks lists the networks found in the whole log, most recent first.
func Networks(dir string) ([]NetInfo, error) {
	all, err := ReadDir(dir, Filter{})
	if err != nil {
		return nil, err
	}
	labels := labelNets(all)
	by := map[string]*NetInfo{}
	srcs := map[string]map[string]bool{}
	prev := ""
	for i, e := range all {
		id := labels[i]
		n := by[id]
		if n == nil {
			n = &NetInfo{ID: id, Class: "", First: e.TimeUTC, Kinds: map[string]int{}}
			by[id] = n
			srcs[id] = map[string]bool{}
		}
		if mid, ok := netMarker(e); ok && mid == id {
			if c := DetailField(e.Detail, "class"); c != "" {
				n.Class = c
			}
			if e.Kind == "net_enter" || prev != id {
				n.Visits++
			}
		}
		prev = id
		n.Last = e.TimeUTC
		if _, isMark := netMarker(e); !isMark {
			n.Lines++
			n.Kinds[e.Kind]++
			if e.Src != "" {
				srcs[id][e.Src] = true
			}
		}
	}
	out := make([]NetInfo, 0, len(by))
	for id, n := range by {
		n.Sources = len(srcs[id])
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return out, nil
}

// netSeqs returns the seq numbers of the lines of network id, judged on the
// whole log (markers outside a case's range still count).
func netSeqs(dir, id string) (map[uint64]bool, error) {
	all, err := ReadDir(dir, Filter{})
	if err != nil {
		return nil, err
	}
	labels := labelNets(all)
	out := map[uint64]bool{}
	for i, e := range all {
		if labels[i] == id {
			out[e.Seq] = true
		}
	}
	return out, nil
}
