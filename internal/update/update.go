// Package update checks GitHub for a newer The Shunt, every few hours.
//
// It only reads public data (the newest commit / release) and sends nothing
// about the machine; still, GitHub sees the request, so it can be turned
// off (tray menu, `shunt ui --no-update-check`, or the file NoCheckFile).
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Repo = "Bob-Nixkoenner/The_Shunt"
	// Command updates an installation (same as the first install).
	Command = "curl -fsSLo install.sh https://raw.githubusercontent.com/" + Repo + "/HEAD/install.sh && sudo bash install.sh"
	Every   = 3 * time.Hour
)

// Info is the result of the last check.
type Info struct {
	Current   string    `json:"current"`       // installed version
	App       string    `json:"app,omitempty"` // version of this running program
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	Command   string    `json:"command,omitempty"`
	Checked   time.Time `json:"checked,omitempty"`
	Err       string    `json:"error,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	// Channels: which kinds of releases are announced.
	Releases    bool `json:"releases"`
	Prereleases bool `json:"prereleases"`
}

// NoCheckFile: if it exists, no checks are made.
func NoCheckFile() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "the-shunt", "no-update-check")
}

// markerFile is a file in the config directory; its existence means "off".
func markerFile(name string) string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "the-shunt", name)
}

func exists(f string) bool {
	if f == "" {
		return false
	}
	_, err := os.Stat(f)
	return err == nil
}

// Releases reports whether stable releases are announced.
func Releases() bool { return Enabled() && !exists(markerFile("no-release-check")) }

// Prereleases reports whether pre-releases (rc, beta) are announced.
func Prereleases() bool { return Enabled() && !exists(markerFile("no-prerelease-check")) }

// Enabled reports whether update checks are on at all.
func Enabled() bool { return !exists(NoCheckFile()) }

func setMarker(f string, off bool) error {
	if f == "" {
		return fmt.Errorf("no config directory")
	}
	if !off {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	return os.WriteFile(f, []byte("delete this file to check for updates again\n"), 0o600)
}

// SetChannels switches stable releases and pre-releases on or off; with
// both off no checks are made.
func SetChannels(releases, pre bool) error {
	if err := setMarker(markerFile("no-release-check"), !releases); err != nil {
		return err
	}
	if err := setMarker(markerFile("no-prerelease-check"), !pre); err != nil {
		return err
	}
	return setMarker(NoCheckFile(), !releases && !pre)
}

// SetEnabled switches all checks on or off (tray menu). Switching on
// restores both channels if none was left on.
func SetEnabled(on bool) error {
	if !on {
		return setMarker(NoCheckFile(), true)
	}
	if err := setMarker(NoCheckFile(), false); err != nil {
		return err
	}
	if exists(markerFile("no-release-check")) && exists(markerFile("no-prerelease-check")) {
		return SetChannels(true, true)
	}
	return nil
}

// Checker checks periodically and remembers the result.
type Checker struct {
	Current string // "src-1a2b3c4" (source build) or "v0.6.0" (release)
	// Installed, if set, returns the version actually installed (the
	// running shuntd); it is compared instead of Current, so an app that
	// was not restarted after an update does not keep announcing it.
	Installed func() string
	// OnAvailable is called once when an update is first found.
	OnAvailable func(Info)
	// API base, for tests.
	API    string
	Client *http.Client

	mu   sync.Mutex
	info Info
}

// Get returns the last result. If the installed version changed since the
// last check (an update was just installed), the old result is void: a new
// check starts in the background.
func (c *Checker) Get() Info {
	inst := ""
	if c.Installed != nil {
		inst = c.Installed()
	}
	c.mu.Lock()
	i := c.info
	if i.Current == "" {
		i.Current = c.Current
	}
	stale := inst != "" && !i.Checked.IsZero() && inst != i.Current
	c.mu.Unlock()
	if stale {
		i.Current, i.Available, i.Command, i.Latest = inst, false, "", ""
		if Enabled() {
			go c.Check(context.Background())
		}
	}
	i.Disabled = !Enabled()
	i.Releases, i.Prereleases = Releases(), Prereleases()
	i.App = c.Current
	return i
}

// Run checks now and then every Every until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	for {
		if Enabled() {
			c.Check(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(Every):
		}
	}
}

// Check asks GitHub once.
func (c *Checker) Check(ctx context.Context) Info {
	cur := c.Current
	if c.Installed != nil {
		if v := c.Installed(); v != "" {
			cur = v
		}
	}
	latest, err := c.latestFor(ctx, cur)
	c.mu.Lock()
	was := c.info.Available
	c.info = Info{Current: cur, Checked: time.Now()}
	if err != nil {
		c.info.Err = err.Error()
	} else {
		c.info.Latest = latest
		c.info.Available = newer(cur, latest)
		if c.info.Available && strings.HasPrefix(cur, "src-") {
			// A source build that is not GitHub's newest commit may be
			// newer (local or pushed work on a branch): only behind counts.
			behind, err := c.behind(ctx, latest, strings.TrimPrefix(cur, "src-"))
			c.info.Available = behind
			if err != nil {
				c.info.Err = err.Error()
			}
		}
		if c.info.Available {
			c.info.Command = Command
		}
	}
	i := c.info
	c.mu.Unlock()
	if i.Available && !was && c.OnAvailable != nil {
		c.OnAvailable(i)
	}
	return i
}

// newer: a source build ("src-<short sha>") is outdated when the newest
// commit differs; a release ("v1.2.3") when the newest release tag differs.
// "dev" builds never ask.
func newer(current, latest string) bool {
	switch {
	case latest == "" || current == "" || current == "dev":
		return false
	case strings.HasPrefix(current, "src-"):
		return !strings.HasPrefix(latest, strings.TrimPrefix(current, "src-"))
	default:
		if c, ok := cmpVersion(latest, current); ok {
			return c > 0
		}
		return latest != current
	}
}

var verRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z]+)\.?(\d+)?)?$`)

// cmpVersion compares "v0.7.0-rc8" style tags: a pre-release is older than
// its release, rc8 is newer than rc7. ok is false for other tag shapes.
func cmpVersion(a, b string) (int, bool) {
	ma, mb := verRe.FindStringSubmatch(a), verRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return map[bool]int{true: 1, false: -1}[x > y], true
		}
	}
	switch {
	case ma[4] == "" && mb[4] == "":
		return 0, true
	case ma[4] == "":
		return 1, true
	case mb[4] == "":
		return -1, true
	}
	if c := strings.Compare(ma[4], mb[4]); c != 0 {
		return c, true
	}
	x, _ := strconv.Atoi(ma[5])
	y, _ := strconv.Atoi(mb[5])
	switch {
	case x > y:
		return 1, true
	case x < y:
		return -1, true
	}
	return 0, true
}

// behind asks GitHub how commit sha relates to the newest commit latest:
// only "behind" or "diverged" (latest has commits sha lacks) is an update.
// A commit GitHub does not know is a local build: no update.
func (c *Checker) behind(ctx context.Context, latest, sha string) (bool, error) {
	base := c.API
	if base == "" {
		base = "https://api.github.com"
	}
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/repos/"+Repo+"/compare/"+latest+"..."+sha+"?per_page=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cl.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, nil // not on GitHub: built from local commits
	default:
		return false, fmt.Errorf("github compare: %s", resp.Status)
	}
	var v struct {
		Status string `json:"status"` // ahead | behind | identical | diverged
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&v); err != nil {
		return false, err
	}
	return v.Status == "behind" || v.Status == "diverged", nil
}

func (c *Checker) latestFor(ctx context.Context, current string) (string, error) {
	base := c.API
	if base == "" {
		base = "https://api.github.com"
	}
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 20 * time.Second}
	}
	path := "/repos/" + Repo + "/releases?per_page=30"
	if strings.HasPrefix(current, "src-") {
		path = "/repos/" + Repo + "/commits/HEAD"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") { // release list
		var rs []struct {
			Tag   string `json:"tag_name"`
			Pre   bool   `json:"prerelease"`
			Draft bool   `json:"draft"`
		}
		if err := json.Unmarshal(b, &rs); err != nil {
			return "", err
		}
		stable, pre := Releases(), Prereleases()
		for _, r := range rs { // newest first
			if r.Draft || (r.Pre && !pre) || (!r.Pre && !stable) {
				continue
			}
			return r.Tag, nil
		}
		return "", nil
	}
	var v struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	return v.SHA, nil
}
