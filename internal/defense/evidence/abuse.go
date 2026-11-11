package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RDAP lookup of the abuse contact of an address. Only ever on a button
// press (never automatic), over the normal route, with a neutral
// user agent. It asks the registry of the address range, never the
// address itself: nothing is sent to the other machine.

const (
	// DefaultBootstrap is the IANA RDAP bootstrap directory.
	DefaultBootstrap = "https://data.iana.org/rdap/"
	// AbuseTimeout bounds one lookup.
	AbuseTimeout = 10 * time.Second
	// AbuseCacheTTL is how long an answer is kept locally.
	AbuseCacheTTL = 7 * 24 * time.Hour
	abuseUA       = "rdap-client"
	abuseMaxBody  = 1 << 20
	// AbuseCacheName is the cache file (0600) in the evidence directory.
	AbuseCacheName = "abuse-cache.json"
)

// AbuseInfo is what the lookup returns.
type AbuseInfo struct {
	IP         string    `json:"ip"`
	Operator   string    `json:"operator,omitempty"` // organisation or network name
	Country    string    `json:"country,omitempty"`
	Network    string    `json:"network,omitempty"` // CIDR or start - end
	Handle     string    `json:"handle,omitempty"`
	AbuseEmail string    `json:"abuse_email,omitempty"`
	Registry   string    `json:"registry,omitempty"` // host of the RDAP server asked
	Fetched    time.Time `json:"fetched"`
	Cached     bool      `json:"cached,omitempty"`
}

// ErrNotPublic is returned for addresses that cannot have a public contact.
var ErrNotPublic = errors.New("not a public address")

// Abuser does the lookups.
type Abuser struct {
	Client    *http.Client // the normal route; nil = default client
	Bootstrap string       // base URL of the bootstrap files
	CacheFile string       // "" = no cache on disk
	AllowHTTP bool         // tests
	Now       func() time.Time

	mu    sync.Mutex
	boots map[string]*bootFile // by "ipv4"/"ipv6"
}

type bootFile struct {
	at       time.Time
	services []bootService
}

type bootService struct {
	prefixes []netip.Prefix
	urls     []string
}

func (a *Abuser) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Abuser) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{}
}

func (a *Abuser) get(ctx context.Context, url string) ([]byte, error) {
	if !a.AllowHTTP && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("only https is used")
	}
	ctx, cancel := context.WithTimeout(ctx, AbuseTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", abuseUA)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, abuseMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > abuseMaxBody {
		return nil, errors.New("answer too large")
	}
	return b, nil
}

func (a *Abuser) bootstrap(ctx context.Context, fam string) (*bootFile, error) {
	a.mu.Lock()
	if bf := a.boots[fam]; bf != nil && a.now().Sub(bf.at) < 24*time.Hour {
		a.mu.Unlock()
		return bf, nil
	}
	a.mu.Unlock()
	base := a.Bootstrap
	if base == "" {
		base = DefaultBootstrap
	}
	b, err := a.get(ctx, strings.TrimSuffix(base, "/")+"/"+fam+".json")
	if err != nil {
		return nil, err
	}
	bf, err := parseBootstrap(b, a.now())
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.boots == nil {
		a.boots = map[string]*bootFile{}
	}
	a.boots[fam] = bf
	a.mu.Unlock()
	return bf, nil
}

func parseBootstrap(b []byte, now time.Time) (*bootFile, error) {
	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("bootstrap file: %w", err)
	}
	bf := &bootFile{at: now}
	for _, s := range raw.Services {
		if len(s) != 2 {
			continue
		}
		var sv bootService
		for _, p := range s[0] {
			if pf, err := netip.ParsePrefix(p); err == nil {
				sv.prefixes = append(sv.prefixes, pf.Masked())
			}
		}
		sv.urls = s[1]
		bf.services = append(bf.services, sv)
	}
	return bf, nil
}

// server picks the registry URL for ip: the longest matching prefix.
func (bf *bootFile) server(ip netip.Addr) string {
	best, bits := "", -1
	for _, s := range bf.services {
		for _, p := range s.prefixes {
			if p.Contains(ip) && p.Bits() > bits && len(s.urls) > 0 {
				best, bits = s.urls[0], p.Bits()
				for _, u := range s.urls { // prefer https
					if strings.HasPrefix(u, "https://") {
						best = u
						break
					}
				}
			}
		}
	}
	return best
}

// Lookup returns the abuse contact of ip, from the local cache when it is
// younger than AbuseCacheTTL.
func (a *Abuser) Lookup(ctx context.Context, ipStr string) (AbuseInfo, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return AbuseInfo{}, errors.New("not an IP address")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return AbuseInfo{}, ErrNotPublic
	}
	key := ip.String()
	cache := a.readCache()
	if c, ok := cache[key]; ok && a.now().Sub(c.Fetched) < AbuseCacheTTL {
		c.Cached = true
		return c, nil
	}
	fam := "ipv4"
	if ip.Is6() {
		fam = "ipv6"
	}
	bf, err := a.bootstrap(ctx, fam)
	if err != nil {
		return AbuseInfo{}, fmt.Errorf("registry directory: %w", err)
	}
	srv := bf.server(ip)
	if srv == "" {
		return AbuseInfo{}, errors.New("no registry known for this address")
	}
	b, err := a.get(ctx, strings.TrimSuffix(srv, "/")+"/ip/"+key)
	if err != nil {
		return AbuseInfo{}, err
	}
	info, err := ParseRDAP(b)
	if err != nil {
		return AbuseInfo{}, err
	}
	info.IP, info.Fetched = key, a.now().UTC()
	if i := strings.Index(srv, "://"); i >= 0 {
		info.Registry = strings.SplitN(srv[i+3:], "/", 2)[0]
	}
	cache[key] = info
	a.writeCache(cache)
	return info, nil
}

// ParseRDAP reads an RDAP "ip network" object.
func ParseRDAP(b []byte) (AbuseInfo, error) {
	var o rdapObj
	if err := json.Unmarshal(b, &o); err != nil {
		return AbuseInfo{}, fmt.Errorf("registry answer: %w", err)
	}
	if o.ObjectClass != "" && o.ObjectClass != "ip network" {
		return AbuseInfo{}, errors.New("registry answer is not an IP network")
	}
	in := AbuseInfo{Operator: o.Name, Country: o.Country, Handle: o.Handle}
	if len(o.Cidrs) > 0 {
		c := o.Cidrs[0]
		if c.V4 != "" {
			in.Network = fmt.Sprintf("%s/%d", c.V4, c.Length)
		} else if c.V6 != "" {
			in.Network = fmt.Sprintf("%s/%d", c.V6, c.Length)
		}
	}
	if in.Network == "" && o.Start != "" {
		in.Network = o.Start + " - " + o.End
	}
	var walk func(es []rdapEnt, depth int)
	walk = func(es []rdapEnt, depth int) {
		for _, e := range es {
			has := func(r string) bool {
				for _, x := range e.Roles {
					if x == r {
						return true
					}
				}
				return false
			}
			fn, mail := e.vcard()
			if has("abuse") && in.AbuseEmail == "" && mail != "" {
				in.AbuseEmail = mail
			}
			if (has("registrant") || has("administrative")) && fn != "" && !strings.Contains(strings.ToLower(in.Operator), strings.ToLower(fn)) {
				in.Operator = fn + " (" + in.Operator + ")"
			}
			if depth < 4 {
				walk(e.Entities, depth+1)
			}
		}
	}
	walk(o.Entities, 0)
	if in.Operator == "" && in.AbuseEmail == "" && in.Network == "" {
		return in, errors.New("registry answer has no usable data")
	}
	return in, nil
}

type rdapObj struct {
	ObjectClass string    `json:"objectClassName"`
	Name        string    `json:"name"`
	Handle      string    `json:"handle"`
	Country     string    `json:"country"`
	Start       string    `json:"startAddress"`
	End         string    `json:"endAddress"`
	Cidrs       []rdapNet `json:"cidr0_cidrs"`
	Entities    []rdapEnt `json:"entities"`
}

type rdapNet struct {
	V4     string `json:"v4prefix"`
	V6     string `json:"v6prefix"`
	Length int    `json:"length"`
}

type rdapEnt struct {
	Roles    []string          `json:"roles"`
	VCard    []json.RawMessage `json:"vcardArray"`
	Entities []rdapEnt         `json:"entities"`
}

// vcard returns the formatted name and the first e-mail address.
func (e rdapEnt) vcard() (fn, mail string) {
	if len(e.VCard) != 2 {
		return "", ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(e.VCard[1], &props) != nil {
		return "", ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, val string
		if json.Unmarshal(p[0], &name) != nil || json.Unmarshal(p[3], &val) != nil {
			continue
		}
		switch name {
		case "fn":
			if fn == "" {
				fn = val
			}
		case "email":
			if mail == "" && strings.Contains(val, "@") && !strings.ContainsAny(val, " <>\"\r\n") {
				mail = val
			}
		}
	}
	return fn, mail
}

func (a *Abuser) readCache() map[string]AbuseInfo {
	out := map[string]AbuseInfo{}
	if a.CacheFile == "" {
		return out
	}
	if b, err := os.ReadFile(a.CacheFile); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	for k, v := range out { // drop what is too old
		if a.now().Sub(v.Fetched) > AbuseCacheTTL {
			delete(out, k)
		}
	}
	return out
}

func (a *Abuser) writeCache(m map[string]AbuseInfo) {
	if a.CacheFile == "" {
		return
	}
	if len(m) > 500 {
		for k := range m {
			delete(m, k)
			if len(m) <= 500 {
				break
			}
		}
	}
	if b, err := json.Marshal(m); err == nil {
		_ = os.MkdirAll(filepath.Dir(a.CacheFile), 0o700)
		_ = writeFileAtomic(a.CacheFile, b)
	}
}
