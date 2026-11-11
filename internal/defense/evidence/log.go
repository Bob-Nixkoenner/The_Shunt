package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ManifestName is the file in the evidence directory that lists the log
// files with the hash each one starts from.
const ManifestName = "chain.json"

// DefaultMaxFileBytes: a log file is closed and a new one started above it.
const DefaultMaxFileBytes = 16 << 20

// maxLineBytes bounds one line when reading (a line is a few hundred bytes).
const maxLineBytes = 64 << 10

// ZeroHash is the prev_hash of the very first line of a chain.
var ZeroHash = strings.Repeat("0", 64)

// Entry is one line of the log. Hash is the SHA-256 (hex) over the line
// text in which the closing `,"hash":"<64 hex>"}` is replaced by `}`; the
// line contains prev_hash, so the lines form a chain.
type Entry struct {
	Seq          uint64 `json:"seq"`
	TimeUTC      string `json:"time_utc"` // RFC 3339 with nanoseconds, UTC
	Kind         string `json:"kind"`
	Severity     string `json:"severity"`
	Src          string `json:"src,omitempty"`
	Port         int    `json:"port,omitempty"`
	Proto        string `json:"proto,omitempty"`
	Detail       string `json:"detail,omitempty"`
	ShuntVersion string `json:"shunt_version"`
	NetClass     string `json:"net_class"`
	PrevHash     string `json:"prev_hash"`
	Hash         string `json:"hash"`
}

// Input is what a caller hands to Append.
type Input struct {
	Time     time.Time // zero = now
	Kind     string
	Severity string
	Src      string
	Port     int
	Proto    string
	Detail   string
}

type entryBody struct {
	Seq          uint64 `json:"seq"`
	TimeUTC      string `json:"time_utc"`
	Kind         string `json:"kind"`
	Severity     string `json:"severity"`
	Src          string `json:"src,omitempty"`
	Port         int    `json:"port,omitempty"`
	Proto        string `json:"proto,omitempty"`
	Detail       string `json:"detail,omitempty"`
	ShuntVersion string `json:"shunt_version"`
	NetClass     string `json:"net_class"`
	PrevHash     string `json:"prev_hash"`
}

var hashSuffix = regexp.MustCompile(`,"hash":"[0-9a-f]{64}"\}$`)

// encodeLine renders e (Hash is ignored and recomputed) as one line without
// the newline.
func encodeLine(e Entry) (string, string, error) {
	b, err := json.Marshal(entryBody{e.Seq, e.TimeUTC, e.Kind, e.Severity, e.Src, e.Port, e.Proto, e.Detail, e.ShuntVersion, e.NetClass, e.PrevHash})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	return string(b[:len(b)-1]) + `,"hash":"` + h + `"}`, h, nil
}

// ParseLine parses one line and checks that its hash matches its text and
// that the text is in canonical form (so the hash covers what was parsed).
func ParseLine(line string) (Entry, error) {
	var e Entry
	if len(line) > maxLineBytes {
		return e, errors.New("line too long")
	}
	loc := hashSuffix.FindStringIndex(line)
	if loc == nil {
		return e, errors.New("no hash member at the end of the line")
	}
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return e, err
	}
	sum := sha256.Sum256([]byte(line[:loc[0]] + "}"))
	if hex.EncodeToString(sum[:]) != e.Hash {
		return e, errors.New("hash does not match the line")
	}
	canon, _, err := encodeLine(e)
	if err != nil || canon != line {
		return e, errors.New("line is not in canonical form")
	}
	return e, nil
}

// FileInfo is one log file in the manifest.
type FileInfo struct {
	Name      string `json:"name"`
	FirstSeq  uint64 `json:"first_seq"`
	StartHash string `json:"start_hash"` // prev_hash of the file's first line
}

// Removed records a seq range that retention or the user deleted, so a gap
// in the chain is not mistaken for tampering.
type Removed struct {
	FirstSeq uint64    `json:"first_seq"`
	LastSeq  uint64    `json:"last_seq"`
	When     time.Time `json:"when"`
}

// Manifest is chain.json.
type Manifest struct {
	Version int        `json:"version"`
	Files   []FileInfo `json:"files"`
	Removed []Removed  `json:"removed,omitempty"`
	// Head is the last line written (survives deleting all files, so the
	// chain and the numbering go on).
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
}

// Options for Open.
type Options struct {
	Version      string           // Shunt version written into every line
	Now          func() time.Time // tests
	MaxFileBytes int64
	// Preamble returns state lines (clock sync status, ...) that are written
	// first into every new file.
	Preamble func() []Input
}

// Log is the append-only event log.
type Log struct {
	dir  string
	opt  Options
	mu   sync.Mutex
	f    *os.File
	name string
	day  string
	size int64
	man  Manifest
	last string // hash of the last line (prev_hash of the next)
	seq  uint64
	cls  string
	// verify cache
	vSeq  uint64
	vNum  int
	vRes  *VerifyReport
	lines int
}

// SafeDir creates dir (0700) and refuses a symbolic link or a directory that
// is not ours, so the log cannot be redirected to a place an attacker chose.
func SafeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	if !ownedByUs(fi) {
		return fmt.Errorf("%s belongs to another user", dir)
	}
	return os.Chmod(dir, 0o700)
}

// Open opens (or creates) the log in dir.
func Open(dir string, opt Options) (*Log, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.MaxFileBytes <= 0 {
		opt.MaxFileBytes = DefaultMaxFileBytes
	}
	if err := SafeDir(dir); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, opt: opt, cls: "unknown"}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) load() error {
	man, err := ReadManifest(l.dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	names, _ := listLogFiles(l.dir)
	if errors.Is(err, os.ErrNotExist) || man.Version == 0 {
		man = Manifest{Version: 1}
	}
	known := map[string]bool{}
	for _, f := range man.Files {
		known[f.Name] = true
	}
	// files without a manifest entry (manifest lost): rebuild from the files
	for _, n := range names {
		if known[n] {
			continue
		}
		es, _ := readFileEntries(filepath.Join(l.dir, n))
		if len(es) > 0 {
			man.Files = append(man.Files, FileInfo{Name: n, FirstSeq: es[0].Seq, StartHash: es[0].PrevHash})
		}
	}
	sort.Slice(man.Files, func(i, j int) bool { return man.Files[i].Name < man.Files[j].Name })
	l.man = man
	l.last, l.seq = ZeroHash, 0
	if man.HeadSeq > 0 {
		l.last, l.seq = man.HeadHash, man.HeadSeq
	}
	if n := len(man.Files); n > 0 {
		es, _ := readFileEntries(filepath.Join(l.dir, man.Files[n-1].Name))
		if len(es) > 0 && es[len(es)-1].Seq >= l.seq {
			l.last, l.seq = es[len(es)-1].Hash, es[len(es)-1].Seq
		}
	}
	return l.writeManifest()
}

// SetNetClass sets the class written into the following lines (trusted,
// public, managed). Never a network name.
func (l *Log) SetNetClass(c string) {
	l.mu.Lock()
	l.cls = c
	l.mu.Unlock()
}

// Dir is the evidence directory.
func (l *Log) Dir() string { return l.dir }

// Append writes one line and returns its seq.
func (l *Log) Append(in Input) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(in, true)
}

func (l *Log) appendLocked(in Input, preamble bool) (uint64, error) {
	now := l.opt.Now().UTC()
	day := now.Format("20060102")
	if l.f != nil && (day != l.day || l.size >= l.opt.MaxFileBytes) {
		l.closeFile()
	}
	if l.f == nil {
		if err := l.openFile(day, now); err != nil {
			return 0, err
		}
		if preamble && l.opt.Preamble != nil {
			for _, p := range l.opt.Preamble() {
				if _, err := l.appendLocked(p, false); err != nil {
					return 0, err
				}
			}
		}
	}
	t := in.Time
	if t.IsZero() {
		t = now
	}
	e := Entry{Seq: l.seq + 1, TimeUTC: t.UTC().Format(time.RFC3339Nano), Kind: in.Kind, Severity: in.Severity,
		Src: in.Src, Port: in.Port, Proto: in.Proto, Detail: in.Detail, ShuntVersion: l.opt.Version, NetClass: l.cls, PrevHash: l.last}
	line, h, err := encodeLine(e)
	if err != nil {
		return 0, err
	}
	n, err := l.f.WriteString(line + "\n")
	l.size += int64(n)
	if err != nil {
		return 0, err
	}
	l.seq, l.last, l.lines = e.Seq, h, l.lines+1
	l.man.HeadSeq, l.man.HeadHash = e.Seq, h
	return e.Seq, nil
}

func (l *Log) openFile(day string, now time.Time) error {
	n := 1
	for {
		l.name = fmt.Sprintf("events-%s-%03d.jsonl", day, n)
		if _, err := os.Lstat(filepath.Join(l.dir, l.name)); errors.Is(err, os.ErrNotExist) {
			break
		}
		n++
		if n > 999 {
			return errors.New("too many log files for one day")
		}
	}
	f, err := os.OpenFile(filepath.Join(l.dir, l.name), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	l.f, l.day, l.size = f, day, 0
	l.man.Files = append(l.man.Files, FileInfo{Name: l.name, FirstSeq: l.seq + 1, StartHash: l.last})
	return l.writeManifest()
}

func (l *Log) closeFile() {
	if l.f != nil {
		_ = l.f.Sync()
		_ = l.f.Close()
		l.f = nil
		_ = l.writeManifest()
	}
}

// Close syncs and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFile()
	return nil
}

func (l *Log) writeManifest() error {
	b, err := json.MarshalIndent(l.man, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(l.dir, ManifestName), b)
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ReadManifest reads chain.json of dir.
func ReadManifest(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%s: %w", ManifestName, err)
	}
	return m, nil
}

var logName = regexp.MustCompile(`^events-\d{8}-\d{3}\.jsonl$`)

func listLogFiles(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		if d.Type().IsRegular() && logName.MatchString(d.Name()) {
			out = append(out, d.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// scanLines calls fn for every line of a file (without parsing).
func scanLines(path string, fn func(n int, line string) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes+16)
	n := 0
	for sc.Scan() {
		n++
		if !fn(n, sc.Text()) {
			return nil
		}
	}
	return sc.Err()
}

// readFileEntries returns the valid leading lines of a file.
func readFileEntries(path string) ([]Entry, error) {
	var out []Entry
	err := scanLines(path, func(_ int, line string) bool {
		e, err := ParseLine(line)
		if err != nil {
			return false
		}
		out = append(out, e)
		return true
	})
	return out, err
}

// Filter selects entries for Read.
type Filter struct {
	Src     string // exact address ("" = any)
	FromSeq uint64
	ToSeq   uint64 // 0 = no upper bound
}

func (f Filter) match(e Entry) bool {
	if e.Seq < f.FromSeq || (f.ToSeq != 0 && e.Seq > f.ToSeq) {
		return false
	}
	return f.Src == "" || e.Src == f.Src
}

// Read returns the entries that match f, oldest first. Lines that do not
// verify are skipped (Verify reports them).
func (l *Log) Read(f Filter) ([]Entry, error) {
	l.mu.Lock()
	if l.f != nil {
		_ = l.f.Sync()
	}
	l.mu.Unlock()
	return ReadDir(l.dir, f)
}

// ReadDir is Read for a directory without an open Log.
func ReadDir(dir string, f Filter) ([]Entry, error) {
	names, err := listLogFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, n := range names {
		_ = scanLines(filepath.Join(dir, n), func(_ int, line string) bool {
			if e, err := ParseLine(line); err == nil && f.match(e) {
				out = append(out, e)
			}
			return true
		})
	}
	return out, nil
}
