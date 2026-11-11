package defense

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Network report: what the defense saw per network, kept locally.
//
// Privacy: the network is only known by the hashed key the daemon derives
// (never a name, SSID or MAC). Source addresses are stored cut to /24 (IPv4)
// or /48 (IPv6), so the file cannot name a single host. The file lives in
// the daemon's state directory with mode 0600 and is never sent anywhere;
// the export is a copy the user saves by hand.

// Network property values (strings so the UI can translate them).
const (
	PropYes      = "yes"       // seen
	PropNoneSeen = "none_seen" // watched, nothing seen so far (not proof)
	PropUnknown  = "unknown"   // not watched or cannot be told
)

// MaxReports is how many networks are remembered (oldest sighting goes first).
const MaxReports = 64

// maxReportSources limits the cut-down source list per network.
const maxReportSources = 50

// NetReport is the report of one network.
type NetReport struct {
	Key       string       `json:"key"` // hashed network key; shortened in the export
	Class     Class        `json:"class"`
	Counts    map[Kind]int `json:"counts"`
	PeakHeat  int          `json:"peak_heat"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	// Properties of the network.
	DNSRedirect string `json:"dns_redirect"` // PropYes / PropNoneSeen / PropUnknown
	Captive     string `json:"captive"`
	Isolation   string `json:"isolation"` // client isolation: not measured yet, always PropUnknown
	// Sources: cut-down source networks (/24, /48) with their event count.
	Sources map[string]int `json:"sources"`
}

// ReportsResponse is what /v1/defense/reports returns (newest first).
type ReportsResponse struct {
	Reports []NetReport `json:"reports"`
	Current string      `json:"current,omitempty"` // key of the network the machine is in now
	Export  bool        `json:"export,omitempty"`  // true when redacted for saving
}

// CutSource shortens a source address to its /24 (IPv4) or /48 (IPv6).
// Anything that is no address gives "".
func CutSource(src string) string {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// Reports keeps the reports and writes them to a file.
type Reports struct {
	mu      sync.Mutex
	path    string // "" = memory only
	byKey   map[string]*NetReport
	cur     string
	dirty   bool
	saveErr error
}

// NewReports loads the file at path (missing or broken = empty). An empty
// path keeps everything in memory.
func NewReports(path string) *Reports {
	r := &Reports{path: path, byKey: map[string]*NetReport{}}
	if path == "" {
		return r
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return r
	}
	var list []NetReport
	if json.Unmarshal(b, &list) != nil {
		return r
	}
	for i := range list {
		x := list[i]
		if x.Key == "" || x.Counts == nil {
			continue
		}
		if x.Sources == nil {
			x.Sources = map[string]int{}
		}
		r.byKey[x.Key] = &x
	}
	r.trim()
	return r
}

func (r *Reports) trim() {
	for len(r.byKey) > MaxReports {
		var old string
		for k, v := range r.byKey {
			if old == "" || v.LastSeen.Before(r.byKey[old].LastSeen) {
				old = k
			}
		}
		delete(r.byKey, old)
	}
}

// Enter marks key as the current network and creates its report. watchDNS
// says whether DNS tampering is being watched.
func (r *Reports) Enter(key string, class Class, now time.Time, watchDNS bool) {
	if key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur = key
	x := r.byKey[key]
	if x == nil {
		x = &NetReport{Key: key, FirstSeen: now, LastSeen: now, Counts: map[Kind]int{}, Sources: map[string]int{},
			DNSRedirect: PropUnknown, Captive: PropUnknown, Isolation: PropUnknown}
		r.byKey[key] = x
		r.trim()
	}
	x.Class, x.LastSeen = class.Normalize(), now
	if watchDNS && x.DNSRedirect == PropUnknown {
		x.DNSRedirect = PropNoneSeen
	}
	if x.Captive == PropUnknown {
		x.Captive = PropNoneSeen // the daemon checks for a portal on every join
	}
	r.dirty = true
}

// Note adds one event (and the heat after it) to the current network.
func (r *Reports) Note(ev Event, heat int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x := r.byKey[r.cur]
	if x == nil {
		return
	}
	x.Counts[ev.Kind]++
	x.LastSeen = ev.Time
	if heat > x.PeakHeat {
		x.PeakHeat = heat
	}
	if ev.Kind == KindDNSHijack {
		x.DNSRedirect = PropYes
	}
	if ev.Kind == KindObservation && strings.HasPrefix(ev.Detail, "captive portal") {
		x.Captive = PropYes
	}
	if c := CutSource(ev.Src); c != "" && ev.Kind != KindBan && ev.Kind != KindUnban {
		if _, ok := x.Sources[c]; ok || len(x.Sources) < maxReportSources {
			x.Sources[c]++
		}
	}
	r.dirty = true
}

// List returns copies, newest sighting first. export=true redacts for
// saving: the key is shortened to 8 characters.
func (r *Reports) List(export bool) ReportsResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]NetReport, 0, len(r.byKey))
	for _, x := range r.byKey {
		c := *x
		c.Counts = make(map[Kind]int, len(x.Counts))
		for k, v := range x.Counts {
			c.Counts[k] = v
		}
		c.Sources = make(map[string]int, len(x.Sources))
		for k, v := range x.Sources {
			c.Sources[k] = v
		}
		if export && len(c.Key) > 8 {
			c.Key = c.Key[:8]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	cur := r.cur
	if export {
		cur = ""
	}
	return ReportsResponse{Reports: out, Current: cur, Export: export}
}

// Flush writes the file if something changed. It returns the write error.
func (r *Reports) Flush() error {
	r.mu.Lock()
	if r.path == "" || !r.dirty {
		r.mu.Unlock()
		return nil
	}
	list := make([]NetReport, 0, len(r.byKey))
	for _, x := range r.byKey {
		list = append(list, *x)
	}
	r.dirty = false
	path := r.path
	b, err := json.Marshal(list)
	r.mu.Unlock()
	if err == nil {
		err = writeFile0600(path, b)
	}
	r.mu.Lock()
	if err != nil {
		r.dirty = true
	}
	r.saveErr = err
	r.mu.Unlock()
	return err
}

func writeFile0600(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
