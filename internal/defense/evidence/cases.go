package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CasesName is the file with the cases (0600).
const CasesName = "cases.json"

// Case marks a set of log lines (one source, from a first line on) the
// user wants to keep and maybe hand over. A pinned case is exempt from
// retention and from the size limit until the user deletes it.
type Case struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Src     string    `json:"src,omitempty"` // exact address; "" = every source
	FromSeq uint64    `json:"from_seq"`
	ToSeq   uint64    `json:"to_seq"` // 0 = open end (later lines of the source join)
	Pinned  bool      `json:"pinned"`
	Created time.Time `json:"created"`
}

// Filter turns the case into a log filter.
func (c Case) Filter() Filter { return Filter{Src: c.Src, FromSeq: c.FromSeq, ToSeq: c.ToSeq} }

// Cases keeps the case list in dir/cases.json.
type Cases struct {
	path string
	mu   sync.Mutex
	list []Case
	now  func() time.Time
}

// OpenCases loads dir/cases.json (absent = empty).
func OpenCases(dir string) (*Cases, error) {
	c := &Cases{path: filepath.Join(dir, CasesName), now: time.Now}
	b, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c.list); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cases) save() error {
	b, err := json.MarshalIndent(c.list, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.path, b)
}

// List returns a copy of the cases.
func (c *Cases) List() []Case {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Case{}, c.list...)
}

// Get returns one case.
func (c *Cases) Get(id string) (Case, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.list {
		if x.ID == id {
			return x, true
		}
	}
	return Case{}, false
}

// MaxCases bounds the list.
const MaxCases = 200

// Create adds a pinned case. src must be an IP address or empty.
func (c *Cases) Create(name, src string, from uint64) (Case, error) {
	if src != "" {
		a, err := netip.ParseAddr(src)
		if err != nil {
			return Case{}, errors.New("src is not an IP address")
		}
		src = a.Unmap().String()
	}
	if len(name) > 120 {
		name = name[:120]
	}
	var id [4]byte
	_, _ = rand.Read(id[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.list) >= MaxCases {
		return Case{}, errors.New("too many cases")
	}
	cs := Case{ID: hex.EncodeToString(id[:]), Name: name, Src: src, FromSeq: from, Pinned: true, Created: c.now().UTC()}
	if cs.Name == "" {
		cs.Name = "case " + cs.ID
	}
	c.list = append(c.list, cs)
	return cs, c.save()
}

// Pin sets or clears the pin of a case.
func (c *Cases) Pin(id string, pinned bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.list {
		if c.list[i].ID == id {
			c.list[i].Pinned = pinned
			return c.save()
		}
	}
	return errors.New("no such case")
}

// Delete removes a case (the log lines stay until retention removes them).
func (c *Cases) Delete(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.list {
		if c.list[i].ID == id {
			c.list = append(c.list[:i], c.list[i+1:]...)
			return c.save()
		}
	}
	return errors.New("no such case")
}

// Protects is a Protect function: true when a pinned case covers a line in
// first..last.
func (c *Cases) Protects(first, last uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.list {
		if x.Pinned && x.FromSeq <= last && (x.ToSeq == 0 || x.ToSeq >= first) {
			return true
		}
	}
	return false
}
