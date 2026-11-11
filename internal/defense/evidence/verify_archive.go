package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxArchiveBytes = 1 << 30 // total size read from an archive
	maxMember       = 600 << 20
)

// VerifyPath checks what path is: a case archive (.tar.gz), a directory that
// holds an unpacked archive (has manifest.json) or a live evidence
// directory (has chain.json).
func VerifyPath(path string) (VerifyReport, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return VerifyReport{}, err
	}
	if fi.IsDir() {
		if _, err := os.Stat(filepath.Join(path, FileManifest)); err == nil {
			files := map[string][]byte{}
			for n := range archiveFiles {
				if b, err := os.ReadFile(filepath.Join(path, n)); err == nil {
					files[n] = b
				}
			}
			return VerifyArchiveFiles(files), nil
		}
		return Verify(path), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return VerifyReport{}, err
	}
	defer f.Close()
	files, err := readArchive(f)
	if err != nil {
		return VerifyReport{}, err
	}
	return VerifyArchiveFiles(files), nil
}

// readArchive reads a .tar.gz into memory. Member names are never used as
// paths; unknown names, links and directories are errors, and the total
// size is bounded.
func readArchive(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, maxArchiveBytes))
	files := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive member %q is not a plain file", h.Name)
		}
		if !archiveFiles[h.Name] { // also rejects every name with a slash or ..
			return nil, fmt.Errorf("unexpected archive member %q", h.Name)
		}
		if _, dup := files[h.Name]; dup {
			return nil, fmt.Errorf("archive member %q twice", h.Name)
		}
		if h.Size < 0 || h.Size > maxMember {
			return nil, fmt.Errorf("archive member %q too large", h.Name)
		}
		total += h.Size
		if total > maxArchiveBytes {
			return nil, fmt.Errorf("archive too large")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return nil, fmt.Errorf("archive member %q is cut off", h.Name)
		}
		files[h.Name] = b
	}
}

// VerifyArchiveFiles checks a case archive held as name -> content: every
// file against manifest.json, every line of events.jsonl (hash, canonical
// form) against chain.jsonl, and the links of chain.jsonl.
func VerifyArchiveFiles(files map[string][]byte) VerifyReport {
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
	mb, ok := files[FileManifest]
	if !ok {
		bad(FileManifest, "missing")
		return r
	}
	var m ArchiveManifest
	if err := json.Unmarshal(mb, &m); err != nil {
		bad(FileManifest, err.Error())
		return r
	}
	listed := map[string]bool{}
	for _, mf := range m.Files {
		listed[mf.Name] = true
		b, ok := files[mf.Name]
		if !ok {
			bad(mf.Name, "listed in the manifest but missing")
			continue
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != mf.SHA256 || len(b) != mf.Bytes {
			bad(mf.Name, "does not match the manifest (changed after export)")
		}
	}
	for n := range files {
		if n != FileManifest && n != FileTimestamp && !listed[n] {
			bad(n, "not listed in the manifest")
		}
	}
	if _, ok := files[FileTimestamp]; ok {
		r.Notes = append(r.Notes, "timestamp.tsr is present; check it with: openssl ts -verify -in timestamp.tsr -data manifest.json -CAfile <authority chain>")
	}
	// chain.jsonl
	chain := map[uint64]ChainRef{}
	var prev *ChainRef
	cb := files[FileChain]
	for i, line := range strings.Split(strings.TrimSpace(string(cb)), "\n") {
		if line == "" {
			continue
		}
		var c ChainRef
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			bad(fmt.Sprintf("%s:%d", FileChain, i+1), err.Error())
			break
		}
		if prev != nil && (c.Seq != prev.Seq+1 || c.PrevHash != prev.Hash) {
			bad(fmt.Sprintf("%s:%d", FileChain, i+1), "chain broken")
		}
		chain[c.Seq] = c
		cc := c
		prev = &cc
	}
	if len(chain) == 0 {
		bad(FileChain, "empty")
	}
	if prev != nil && (prev.Seq != m.LastSeq || chain[m.FirstSeq].Seq != m.FirstSeq) {
		bad(FileChain, "does not span the seq range named in the manifest")
	}
	// events.jsonl
	var lastSeq uint64
	for i, line := range strings.Split(strings.TrimSuffix(string(files[FileEvents]), "\n"), "\n") {
		where := fmt.Sprintf("%s:%d", FileEvents, i+1)
		e, err := ParseLine(line)
		if err != nil {
			bad(where, err.Error())
			break
		}
		r.Lines++
		if e.Seq <= lastSeq {
			bad(where, "seq not increasing")
		}
		lastSeq = e.Seq
		if c, ok := chain[e.Seq]; !ok || c.Hash != e.Hash || c.PrevHash != e.PrevHash {
			bad(where, "line is not part of the chain in chain.jsonl")
		}
	}
	if cp, ok := files[FileCapture]; ok {
		if _, err := ReadPcap(bytes.NewReader(cp)); err != nil {
			bad(FileCapture, err.Error())
		}
	}
	r.Files = len(files)
	return r
}
