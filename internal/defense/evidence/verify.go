package evidence

import (
	"fmt"
	"path/filepath"
	"sort"
)

// VerifyReport is the result of Verify.
type VerifyReport struct {
	OK       bool     `json:"ok"`
	Files    int      `json:"files"`
	Lines    int      `json:"lines"`
	FirstBad string   `json:"first_bad,omitempty"` // "file:line: why" of the first broken line
	Problems []string `json:"problems,omitempty"`
	Notes    []string `json:"notes,omitempty"` // e.g. ranges removed by retention
}

// Verify checks every line (hash and canonical form), the links between
// lines (prev_hash), the start hash of each file against the manifest and
// the continuity between files. Gaps are fine only where the manifest
// records a removal. It reports the first broken line.
//
// Limit: whoever can rewrite the whole directory (log and manifest) can
// forge a consistent chain. The hash of the head (shown in the status and
// in an export, and covered by an optional RFC 3161 time stamp) is what an
// outsider can hold the chain against.
func Verify(dir string) VerifyReport {
	r := VerifyReport{OK: true}
	bad := func(where, why string) {
		r.OK = false
		msg := where + ": " + why
		if r.FirstBad == "" {
			r.FirstBad = msg
		}
		if len(r.Problems) < 20 {
			r.Problems = append(r.Problems, msg)
		}
	}
	man, err := ReadManifest(dir)
	if err != nil {
		bad(ManifestName, err.Error())
		return r
	}
	names, err := listLogFiles(dir)
	if err != nil {
		bad(dir, err.Error())
		return r
	}
	start := map[string]FileInfo{}
	for _, f := range man.Files {
		start[f.Name] = f
	}
	for _, n := range names {
		if _, ok := start[n]; !ok {
			bad(n, "file is not in the manifest")
		}
	}
	for _, f := range man.Files {
		found := false
		for _, n := range names {
			if n == f.Name {
				found = true
			}
		}
		if !found {
			bad(f.Name, "file listed in the manifest is missing (not recorded as removed)")
		}
	}
	rm := man.Removed
	covered := func(a, b uint64) bool { // is [a,b] inside one removed range or a union of them
		sort.Slice(rm, func(i, j int) bool { return rm[i].FirstSeq < rm[j].FirstSeq })
		cur := a
		for _, x := range rm {
			if x.FirstSeq <= cur && x.LastSeq >= cur {
				cur = x.LastSeq + 1
			}
		}
		return cur > b
	}
	for _, x := range rm {
		r.Notes = append(r.Notes, fmt.Sprintf("seq %d-%d removed on %s", x.FirstSeq, x.LastSeq, x.When.UTC().Format("2006-01-02")))
	}
	var prevHash string
	var prevSeq uint64
	first := true
	for _, n := range names {
		info, ok := start[n]
		if !ok {
			continue
		}
		r.Files++
		lineNo := 0
		fileFirst := true
		err := scanLines(filepath.Join(dir, n), func(_ int, line string) bool {
			lineNo++
			where := fmt.Sprintf("%s:%d", n, lineNo)
			e, err := ParseLine(line)
			if err != nil {
				bad(where, err.Error())
				return false
			}
			r.Lines++
			if fileFirst {
				fileFirst = false
				if e.PrevHash != info.StartHash || e.Seq != info.FirstSeq {
					bad(where, "first line does not match the manifest")
				}
				switch {
				case first:
					// the oldest file starts wherever retention cut the chain
				case prevSeq+1 == e.Seq:
					if e.PrevHash != prevHash {
						bad(where, "chain broken between files")
					}
				case e.Seq > prevSeq+1:
					if !covered(prevSeq+1, e.Seq-1) {
						bad(where, fmt.Sprintf("lines %d-%d are missing and not recorded as removed", prevSeq+1, e.Seq-1))
					}
				default:
					bad(where, "seq goes backwards between files")
				}
			} else {
				if e.Seq != prevSeq+1 {
					bad(where, fmt.Sprintf("seq %d after %d", e.Seq, prevSeq))
				}
				if e.PrevHash != prevHash {
					bad(where, "prev_hash does not match the line before")
				}
			}
			first = false
			prevHash, prevSeq = e.Hash, e.Seq
			return true
		})
		if err != nil {
			bad(n, err.Error())
		}
	}
	if man.HeadSeq > 0 && r.Lines > 0 && prevSeq < man.HeadSeq && !covered(prevSeq+1, man.HeadSeq) {
		bad(ManifestName, fmt.Sprintf("head is seq %d but the log ends at %d (lines cut off at the end)", man.HeadSeq, prevSeq))
	}
	if man.HeadSeq > 0 && r.Lines > 0 && prevSeq == man.HeadSeq && prevHash != man.HeadHash {
		bad(ManifestName, "head hash does not match the last line")
	}
	return r
}

// Status of the log for the API.
type Status struct {
	Open     bool     `json:"open"`
	Files    int      `json:"files"`
	Lines    int      `json:"lines"`
	Bytes    int64    `json:"bytes"`
	ChainOK  bool     `json:"chain_ok"`
	FirstBad string   `json:"first_bad,omitempty"`
	HeadSeq  uint64   `json:"head_seq"`
	HeadHash string   `json:"head_hash,omitempty"`
	PcapSize int64    `json:"pcap_bytes"`
	Notes    []string `json:"notes,omitempty"`
}

// Status verifies the chain (cached until the head moves) and sums sizes.
func (l *Log) Status() Status {
	l.mu.Lock()
	if l.f != nil {
		_ = l.f.Sync()
	}
	seq, nf := l.seq, len(l.man.Files)
	cached := l.vRes != nil && l.vSeq == seq && l.vNum == nf
	l.mu.Unlock()
	if !cached {
		r := Verify(l.dir)
		l.mu.Lock()
		l.vRes, l.vSeq, l.vNum = &r, seq, nf
		l.mu.Unlock()
	}
	l.mu.Lock()
	r := *l.vRes
	st := Status{Open: true, Files: r.Files, Lines: r.Lines, ChainOK: r.OK, FirstBad: r.FirstBad, HeadSeq: l.man.HeadSeq, HeadHash: l.man.HeadHash, Notes: r.Notes}
	l.mu.Unlock()
	names, _ := listLogFiles(l.dir)
	for _, n := range names {
		st.Bytes += fileSize(filepath.Join(l.dir, n))
	}
	st.PcapSize = dirSize(filepath.Join(l.dir, PcapDir))
	return st
}

// StatusOfDir is Status for a directory without an open Log (evidence off).
func StatusOfDir(dir string) Status {
	r := Verify(dir)
	st := Status{Files: r.Files, Lines: r.Lines, ChainOK: r.OK, FirstBad: r.FirstBad, Notes: r.Notes}
	if m, err := ReadManifest(dir); err == nil {
		st.HeadSeq, st.HeadHash = m.HeadSeq, m.HeadHash
	} else if r.Lines == 0 && len(r.Problems) > 0 {
		st.ChainOK = true // no log yet
		st.FirstBad = ""
	}
	names, _ := listLogFiles(dir)
	for _, n := range names {
		st.Bytes += fileSize(filepath.Join(dir, n))
	}
	st.PcapSize = dirSize(filepath.Join(dir, PcapDir))
	return st
}

// Sync flushes the open file to disk (before an export reads it).
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Sync()
	}
	return nil
}
