package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Names inside a case archive. They are fixed: the archive is only ever
// written with these names and only ever read into memory by them, so a
// crafted archive cannot write anywhere (no path from the archive is used).
const (
	FileEvents    = "events.jsonl"
	FileChain     = "chain.jsonl"
	FileCapture   = "capture.pcapng"
	FileManifest  = "manifest.json"
	FileReadme    = "README.txt"
	FileAddrTXT   = "addresses.txt"
	FileAddrCSV   = "addresses.csv"
	FileTimestamp = "timestamp.tsr"
	// ExportsDir holds finished archives (0700, inside the evidence dir).
	ExportsDir = "exports"
)

var archiveFiles = map[string]bool{FileEvents: true, FileChain: true, FileCapture: true, FileManifest: true,
	FileReadme: true, FileAddrTXT: true, FileAddrCSV: true, FileTimestamp: true}

// ExportOptions says what to export.
type ExportOptions struct {
	Dir     string // evidence directory
	Case    *Case  // a case, or
	Src     string // one source address
	OutDir  string // default Dir/exports
	Version string
	Build   string // build hash ("" = from the binary)
	// TSA, when set, is an https URL of an RFC 3161 time stamp authority;
	// only the SHA-256 of manifest.json is sent, and only here, on export.
	TSA       string
	TSAClient *http.Client
	// Net limits the export to the lines of one network (label from
	// Networks). Empty = every network; the service refuses that unless the
	// caller asked for it on purpose.
	Net string
	// Anonymize leaves out what describes this computer: the packet capture
	// (it can hold this computer's hardware address) and the program, system
	// and build details in the manifest. The log lines stay as they are,
	// because their hashes would break otherwise.
	Anonymize   bool
	ClockSynced func() (synced, known bool)
	Now         func() time.Time
}

// ExportResult describes the archive.
type ExportResult struct {
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	Lines       int    `json:"lines"`
	Packets     int    `json:"packets"`
	Addresses   int    `json:"addresses"`
	Timestamped bool   `json:"timestamped"`
	Note        string `json:"note,omitempty"`
}

// ChainRef is one line of chain.jsonl.
type ChainRef struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// ManifestFile is one file of the archive in manifest.json.
type ManifestFile struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ArchiveManifest is manifest.json of a case archive.
type ArchiveManifest struct {
	Format  int    `json:"format"`
	Created string `json:"created_utc"`
	Case    struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
		Src  string `json:"src,omitempty"`
	} `json:"case"`
	FirstTime  string `json:"first_event_utc,omitempty"`
	LastTime   string `json:"last_event_utc,omitempty"`
	FirstSeq   uint64 `json:"first_seq"`
	LastSeq    uint64 `json:"last_seq"`
	TimeSource string `json:"time_source"`
	Tool       struct {
		Shunt string `json:"shunt_version"`
		Build string `json:"build"`
		Go    string `json:"go_version"`
	} `json:"tool"`
	Host struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"host"`
	Files []ManifestFile `json:"files"`
}

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func buildHash() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}

// selectEntries applies the case or source and the network choice.
func selectEntries(o ExportOptions) (Case, []Entry, error) {
	var f Filter
	var cs Case
	if o.Case != nil {
		cs = *o.Case
		f = cs.Filter()
	} else if o.Src != "" {
		a, err := netip.ParseAddr(o.Src)
		if err != nil {
			return cs, nil, errors.New("src is not an IP address")
		}
		cs.Src = a.Unmap().String()
		f = Filter{Src: cs.Src}
	} else {
		return cs, nil, errors.New("a case or a source address is needed")
	}
	entries, err := ReadDir(o.Dir, f)
	if err != nil {
		return cs, nil, err
	}
	if o.Net != "" {
		seqs, err := netSeqs(o.Dir, o.Net)
		if err != nil {
			return cs, nil, err
		}
		kept := entries[:0:0]
		for _, e := range entries {
			if seqs[e.Seq] {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	if len(entries) == 0 {
		return cs, nil, errors.New("no log lines for this case (retention may have removed them)")
	}
	return cs, entries, nil
}

// ExportPlan says what an export would hold, without writing anything.
type ExportPlan struct {
	Lines     int      `json:"lines"`
	Sources   int      `json:"sources"`
	Packets   int      `json:"packets"`
	First     string   `json:"first_utc"`
	Last      string   `json:"last_utc"`
	Kinds     []string `json:"kinds"`
	ChainOnly int      `json:"chain_only"` // lines of other networks or sources, as hashes only
	Files     []string `json:"files"`
	Net       string   `json:"net,omitempty"`
	Anonymize bool     `json:"anonymize"`
	TSA       bool     `json:"timestamp"`
}

// Plan lists what Export would write for o.
func Plan(o ExportOptions) (ExportPlan, error) {
	var p ExportPlan
	cs, entries, err := selectEntries(o)
	if err != nil {
		return p, err
	}
	span, _ := ReadDir(o.Dir, Filter{FromSeq: entries[0].Seq, ToSeq: entries[len(entries)-1].Seq})
	srcs := map[string]bool{}
	kinds := map[string]bool{}
	seqs := map[uint64]bool{}
	for _, e := range entries {
		seqs[e.Seq] = true
		kinds[e.Kind] = true
		if e.Src != "" {
			srcs[e.Src] = true
		}
	}
	p.Lines, p.Sources, p.Net, p.Anonymize, p.TSA = len(entries), len(srcs), o.Net, o.Anonymize, o.TSA != ""
	p.First, p.Last = entries[0].TimeUTC, entries[len(entries)-1].TimeUTC
	p.ChainOnly = len(span) - len(entries)
	if p.ChainOnly < 0 {
		p.ChainOnly = 0
	}
	for k := range kinds {
		p.Kinds = append(p.Kinds, k)
	}
	sort.Strings(p.Kinds)
	p.Files = []string{FileEvents, FileChain, FileAddrTXT, FileAddrCSV, FileReadme, FileManifest}
	if !o.Anonymize {
		_, p.Packets = mergeCapture(filepath.Join(o.Dir, PcapDir), seqs, cs.Src)
		if p.Packets > 0 {
			p.Files = append(p.Files, FileCapture)
		}
	}
	if p.TSA {
		p.Files = append(p.Files, FileTimestamp)
	}
	return p, nil
}

// Export writes a case archive (.tar.gz) and returns where it is.
func Export(ctx context.Context, o ExportOptions) (ExportResult, error) {
	var res ExportResult
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	cs, entries, err := selectEntries(o)
	if err != nil {
		return res, err
	}
	// the evidence for the whole span, to prove the chain around the
	// selected lines (hashes only)
	span, _ := ReadDir(o.Dir, Filter{FromSeq: entries[0].Seq, ToSeq: entries[len(entries)-1].Seq})

	var events, chain bytes.Buffer
	for _, e := range entries {
		line, _, _ := encodeLine(e)
		events.WriteString(line + "\n")
	}
	enc := json.NewEncoder(&chain)
	for _, e := range span {
		_ = enc.Encode(ChainRef{e.Seq, e.PrevHash, e.Hash})
	}
	seqs := map[uint64]bool{}
	for _, e := range entries {
		seqs[e.Seq] = true
	}
	var capData []byte
	npk := 0
	if !o.Anonymize {
		capData, npk = mergeCapture(filepath.Join(o.Dir, PcapDir), seqs, cs.Src)
	}

	files := []archiveFile{{FileEvents, events.Bytes()}, {FileChain, chain.Bytes()}}
	if npk > 0 {
		files = append(files, archiveFile{FileCapture, capData})
	}
	txt, csvb, naddr := addressLists(entries)
	files = append(files, archiveFile{FileAddrTXT, txt}, archiveFile{FileAddrCSV, csvb})
	files = append(files, archiveFile{FileReadme, []byte(readme(npk > 0, o.Anonymize))})

	var m ArchiveManifest
	m.Format = 1
	m.Created = now().UTC().Format(time.RFC3339)
	m.Case.ID, m.Case.Name, m.Case.Src = cs.ID, cs.Name, cs.Src
	m.FirstTime, m.LastTime = entries[0].TimeUTC, entries[len(entries)-1].TimeUTC
	m.FirstSeq, m.LastSeq = entries[0].Seq, entries[len(entries)-1].Seq
	sync := "unknown"
	if o.ClockSynced != nil {
		if s, known := o.ClockSynced(); known {
			sync = map[bool]string{true: "yes", false: "NO"}[s]
		}
	}
	m.TimeSource = "system clock (UTC), NTP synchronised at export: " + sync + "; see state_clock and clock_jump lines in events.jsonl"
	if !o.Anonymize {
		m.Tool.Shunt, m.Tool.Go = o.Version, runtime.Version()
		m.Tool.Build = o.Build
		if m.Tool.Build == "" {
			m.Tool.Build = buildHash()
		}
		m.Host.OS, m.Host.Arch = runtime.GOOS, runtime.GOARCH // never the host name
	}
	for _, af := range files {
		s := sha256.Sum256(af.data)
		m.Files = append(m.Files, ManifestFile{af.name, len(af.data), hex.EncodeToString(s[:])})
	}
	mb, _ := json.MarshalIndent(m, "", " ")
	files = append(files, archiveFile{FileManifest, mb})

	res.Lines, res.Packets, res.Addresses = len(entries), npk, naddr
	if o.TSA != "" {
		if tsr, err := timestamp(ctx, o.TSA, o.TSAClient, mb); err == nil {
			files = append(files, archiveFile{FileTimestamp, tsr})
			res.Timestamped = true
		} else {
			res.Note = "time stamp not added: " + err.Error()
		}
	}

	out := o.OutDir
	if out == "" {
		out = filepath.Join(o.Dir, ExportsDir)
	}
	if err := SafeDir(out); err != nil {
		return res, err
	}
	var rnd [3]byte
	_, _ = rand.Read(rnd[:])
	label := cs.ID
	if label == "" {
		label = strings.ReplaceAll(cs.Src, ":", "-")
	}
	name := fmt.Sprintf("shunt-case-%s-%s-%x.tar.gz", safeName.ReplaceAllString(label, "_"), now().UTC().Format("20060102T150405Z"), rnd)
	path := filepath.Join(out, name)
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return res, err
	}
	h := sha256.New()
	cw := io.MultiWriter(fh, h)
	if err := writeTarGz(cw, files, now()); err != nil {
		fh.Close()
		os.Remove(path)
		return res, err
	}
	if err := fh.Close(); err != nil {
		os.Remove(path)
		return res, err
	}
	res.Path, res.SHA256 = path, hex.EncodeToString(h.Sum(nil))
	res.Bytes = fileSize(path)
	return res, nil
}

type archiveFile struct {
	name string
	data []byte
}

func writeTarGz(w io.Writer, files []archiveFile, mod time.Time) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if !archiveFiles[f.name] {
			return errors.New("internal: unknown archive member " + f.name)
		}
		hdr := &tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.data)), ModTime: mod.UTC(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(f.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// ipSrc extracts the source address of a raw IP packet.
func ipSrc(b []byte) (netip.Addr, bool) {
	if len(b) >= 20 && b[0]>>4 == 4 {
		a, ok := netip.AddrFromSlice(b[12:16])
		return a, ok
	}
	if len(b) >= 40 && b[0]>>4 == 6 {
		a, ok := netip.AddrFromSlice(b[8:24])
		return a.Unmap(), ok
	}
	return netip.Addr{}, false
}

// mergeCapture collects the packets of all capture files that are labelled
// with one of the case's events. With a source address, unsolicited inbound
// packets of other sources are left out; control frames of the window stay.
func mergeCapture(dir string, seqs map[uint64]bool, src string) ([]byte, int) {
	var all []Packet
	for _, n := range PcapFiles(dir) {
		fh, err := os.Open(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		ps, _ := ReadPcap(io.LimitReader(fh, 512<<20))
		fh.Close()
		for _, p := range ps {
			if !strings.HasPrefix(p.Comment, "event=") {
				continue
			}
			s, err := strconv.ParseUint(strings.TrimPrefix(p.Comment, "event="), 10, 64)
			if err != nil || !seqs[s] {
				continue
			}
			if src != "" && p.Link == LinkRaw {
				if a, ok := ipSrc(p.Data); !ok || a.String() != src {
					continue
				}
			}
			all = append(all, p)
		}
	}
	if len(all) == 0 {
		return nil, 0
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	var buf bytes.Buffer
	w, err := NewPcapWriter(&buf, "The Shunt evidence export")
	if err != nil {
		return nil, 0
	}
	eth, _ := w.AddInterface(LinkEthernet, SnapControl, "control frames")
	raw, _ := w.AddInterface(LinkRaw, SnapInbound, "unsolicited inbound")
	for _, p := range all {
		id := eth
		if p.Link == LinkRaw {
			id = raw
		}
		_ = w.WritePacket(id, p.Time, p.Data, p.OrigLen, p.Comment)
	}
	return buf.Bytes(), len(all)
}

// addressLists makes addresses.txt (one address per line, for tools that
// read a host list) and addresses.csv from the events' sources.
func addressLists(es []Entry) (txt, csvb []byte, n int) {
	type st struct {
		count       int
		first, last string
	}
	m := map[string]*st{}
	for _, e := range es {
		if e.Src == "" {
			continue
		}
		if _, err := netip.ParseAddr(e.Src); err != nil {
			continue
		}
		s := m[e.Src]
		if s == nil {
			s = &st{first: e.TimeUTC}
			m[e.Src] = s
		}
		s.count++
		s.last = e.TimeUTC
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var tb, cb bytes.Buffer
	cw := csv.NewWriter(&cb)
	_ = cw.Write([]string{"address", "events", "first_seen_utc", "last_seen_utc"})
	for _, k := range keys {
		tb.WriteString(k + "\n")
		_ = cw.Write([]string{k, strconv.Itoa(m[k].count), m[k].first, m[k].last})
	}
	cw.Flush()
	return tb.Bytes(), cb.Bytes(), len(keys)
}

func readme(haveCapture, anonymous bool) string {
	cap := "capture.pcapng is not part of this archive (no packet capture was running, or none was labelled with these events)."
	if haveCapture {
		cap = "capture.pcapng holds the packets recorded around these events (open it with Wireshark, Zeek or Suricata). Each packet carries the comment \"event=<seq>\", the seq of the log line that caused it. It contains only unsolicited inbound packets (first packet of a connection to a decoy or closed port, payload cut to 128 bytes) and incoming ARP/DHCP/IPv6 router and neighbour frames. Control frames can contain hardware addresses of devices on the network, including this computer: look at it before you pass it on."
	}
	if anonymous {
		cap = "capture.pcapng is not part of this archive on purpose (it can hold the hardware address of this computer). The manifest names no program, system or build."
	}
	return `THE SHUNT - CASE ARCHIVE

What this is
  A copy of the log lines of one case, recorded by The Shunt's defense on one
  computer, plus what is needed to check that they were not changed.
  This is a technical record, not legal advice. Whether it can be used in
  court depends on the case and the country. Before you act on a serious
  finding, ask the police, a lawyer or your IT security office.

Files
  events.jsonl    the log lines of this case, one JSON object per line, UTC.
  chain.jsonl     seq, prev_hash and hash of every log line from the first to
                  the last line of this case (also those of other sources, as
                  hashes only). It proves the lines of events.jsonl belong to
                  one unbroken chain.
  manifest.json   SHA-256 of every file, time span, time source, version of
                  the program, Go version, operating system (no computer name).
  addresses.txt / addresses.csv
                  the source addresses with count and first/last sighting,
                  for tools that take a host list (for example whois).
                  The Shunt never scans anyone. Scanning other people's
                  computers can be illegal; do not do it without advice.
  ` + cap + `
  timestamp.tsr   (only if set up) an RFC 3161 time stamp over manifest.json,
                  issued by a time stamp authority. Only the hash was sent.

How to check it
  1. Easiest: "shunt evidence verify <this archive>" (no running service
     needed). It checks every file against manifest.json, every line's hash
     and the chain.
  2. By hand: sha256sum each file and compare with manifest.json. A line's
     hash is the SHA-256 of the line text in which the ending
     ,"hash":"<64 hex digits>"} is replaced by }. The prev_hash of a line
     equals the hash of the line before it (the first line of a log starts
     from 64 zeros or from the hash of an older, deleted line).
  3. With a time stamp: openssl ts -verify -in timestamp.tsr -data manifest.json
     -CAfile <the authority's certificate chain>

What was NOT collected
  No normal internet traffic, nothing outgoing, no content of connections you
  made, no passwords (a fake login records only the length and the start of a
  hash), no name, SSID or hardware address of the network you were in, no
  addresses of this computer, no scans of the other side.
  Source addresses are personal data under many laws; use them for reporting
  and prosecution only, and delete what you no longer need.

Limits
  Whoever can change all files on the computer can build a consistent fake
  chain. The time stamp (timestamp.tsr) or a hash you gave to someone else
  earlier is what protects against that. The clock of the computer was the
  time source; the lines state_clock and clock_jump in events.jsonl show
  whether it was synchronised and whether it jumped.
`
}

// ---- RFC 3161 time stamp (request built by hand, DER) ----

func timestampRequest(digest [32]byte, nonce [8]byte) []byte {
	algID := []byte{0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00}
	imprint := append([]byte{0x30, 0x31}, algID...)
	imprint = append(imprint, 0x04, 0x20)
	imprint = append(imprint, digest[:]...)
	body := []byte{0x02, 0x01, 0x01}
	body = append(body, imprint...)
	nonce[0] &= 0x7f // positive INTEGER
	body = append(body, 0x02, 0x08)
	body = append(body, nonce[:]...)
	body = append(body, 0x01, 0x01, 0xff) // certReq TRUE
	return append([]byte{0x30, byte(len(body))}, body...)
}

// timestampGranted reads the PKIStatus of a TimeStampResp (0 or 1 = granted).
func timestampGranted(b []byte) bool {
	// SEQUENCE { SEQUENCE { INTEGER status ... } ... }
	skip := func(b []byte) ([]byte, bool) { // enter a constructed element
		if len(b) < 2 || b[0] != 0x30 {
			return nil, false
		}
		l := int(b[1])
		off := 2
		if l&0x80 != 0 {
			n := l & 0x7f
			if n < 1 || n > 3 || len(b) < 2+n {
				return nil, false
			}
			l = 0
			for i := 0; i < n; i++ {
				l = l<<8 | int(b[2+i])
			}
			off = 2 + n
		}
		if len(b) < off+l {
			return nil, false
		}
		return b[off : off+l], true
	}
	in, ok := skip(b)
	if !ok {
		return false
	}
	st, ok := skip(in)
	if !ok || len(st) < 3 || st[0] != 0x02 || st[1] != 0x01 {
		return false
	}
	return st[2] == 0 || st[2] == 1
}

func timestamp(ctx context.Context, url string, cl *http.Client, manifest []byte) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("the time stamp authority must be an https URL")
	}
	if cl == nil {
		cl = &http.Client{}
	}
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	req := timestampRequest(sha256.Sum256(manifest), nonce)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/timestamp-query")
	r.Header.Set("Accept", "application/timestamp-reply")
	r.Header.Set("User-Agent", abuseUA)
	resp, err := cl.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authority answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if !timestampGranted(b) {
		return nil, errors.New("authority refused the request")
	}
	return b, nil
}
