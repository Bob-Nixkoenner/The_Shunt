package evidence

import (
	"os"
	"path/filepath"
	"sort"
	"time"
)

// PcapDir is the sub-directory of captures.
const PcapDir = "pcap"

func fileSize(p string) int64 {
	if fi, err := os.Lstat(p); err == nil {
		return fi.Size()
	}
	return 0
}

func dirSize(dir string) int64 {
	var n int64
	des, _ := os.ReadDir(dir)
	for _, d := range des {
		if d.Type().IsRegular() {
			n += fileSize(filepath.Join(dir, d.Name()))
		}
	}
	return n
}

// Protect says whether any line in the seq range first..last belongs to a
// pinned case (such a file is never deleted).
type Protect func(first, last uint64) bool

// Prune deletes closed log files older than retention (0 = keep all by
// age) and then, oldest first, as many as it takes to get under maxBytes
// (0 = no limit). A file that holds a line of a pinned case is never
// deleted. The open file is never touched. It records what it removed.
func (l *Log) Prune(retention time.Duration, maxBytes int64, protect Protect) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := ""
	if l.f != nil {
		cur = l.name
	}
	now := l.opt.Now()
	type cand struct {
		i        int
		size     int64
		old      bool
		fileLast uint64
	}
	var cs []cand
	total := dirSize(l.dir)
	files := l.man.Files
	for i, f := range files {
		if f.Name == cur {
			continue
		}
		last := l.man.HeadSeq
		if i+1 < len(files) {
			last = files[i+1].FirstSeq - 1
		}
		old := false
		if t, err := time.Parse("20060102", f.Name[len("events-"):len("events-")+8]); err == nil && retention > 0 {
			old = now.Sub(t.Add(24*time.Hour)) > retention
		}
		cs = append(cs, cand{i: i, size: fileSize(filepath.Join(l.dir, f.Name)), old: old, fileLast: last})
	}
	protected := func(c cand) bool { return protect != nil && protect(files[c.i].FirstSeq, c.fileLast) }
	sort.Slice(cs, func(a, b int) bool { return cs[a].i < cs[b].i })
	del := map[int]bool{}
	for _, c := range cs {
		if c.old && !protected(c) {
			del[c.i] = true
			total -= c.size
		}
	}
	if maxBytes > 0 {
		for _, c := range cs {
			if total <= maxBytes {
				break
			}
			if !del[c.i] && !protected(c) {
				del[c.i] = true
				total -= c.size
			}
		}
	}
	return l.removeLocked(del, nil)
}

// removeLocked deletes the files at the given manifest indexes.
func (l *Log) removeLocked(del map[int]bool, _ any) (int, error) {
	if len(del) == 0 {
		return 0, nil
	}
	var keep []FileInfo
	n := 0
	for i, f := range l.man.Files {
		if !del[i] {
			keep = append(keep, f)
			continue
		}
		last := l.man.HeadSeq
		if i+1 < len(l.man.Files) {
			last = l.man.Files[i+1].FirstSeq - 1
		}
		if err := os.Remove(filepath.Join(l.dir, f.Name)); err != nil && !os.IsNotExist(err) {
			keep = append(keep, f)
			continue
		}
		l.man.Removed = append(l.man.Removed, Removed{FirstSeq: f.FirstSeq, LastSeq: last, When: l.opt.Now().UTC()})
		n++
	}
	l.man.Files = keep
	l.man.Removed = mergeRemoved(l.man.Removed)
	l.vRes = nil
	return n, l.writeManifest()
}

func mergeRemoved(r []Removed) []Removed {
	sort.Slice(r, func(i, j int) bool { return r[i].FirstSeq < r[j].FirstSeq })
	var out []Removed
	for _, x := range r {
		if n := len(out); n > 0 && x.FirstSeq <= out[n-1].LastSeq+1 {
			if x.LastSeq > out[n-1].LastSeq {
				out[n-1].LastSeq = x.LastSeq
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

// Purge deletes every closed file that holds no pinned line (all = true:
// pinned ones too, and the open file is closed first) and the captures
// under the same rule. It returns the number of log files removed.
func (l *Log) Purge(all bool, protect Protect) (int, error) {
	l.mu.Lock()
	l.closeFile()
	l.mu.Unlock()
	if all {
		protect = nil
	}
	n, err := l.Prune(0, 1, protect) // maxBytes 1: delete everything not protected
	if err != nil {
		return n, err
	}
	PrunePcap(filepath.Join(l.dir, PcapDir), 1, protect)
	return n, nil
}
