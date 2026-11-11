package defense

import (
	"os"
	"path/filepath"
	"time"
)

// CacheFile is the file a source is kept in (the same name Updater uses),
// so a platform that downloads the lists itself (Android: Kotlin, because Go
// has no system resolver there) writes exactly where LoadCache reads.
func CacheFile(dir string, s Source) string {
	return filepath.Join(dir, "rep-"+filepath.Base(s.Name)+".txt")
}

// LoadCache loads the cached file of every source in srcs without any
// download. Expiry counts from the file's age (as after a failed download).
// A missing file is recorded as an error in the source's status; entries of
// a source that is not in srcs are dropped. It returns the number of lists
// that were loaded.
func (u *Updater) LoadCache(srcs []Source) int {
	loaded := 0
	for _, s := range srcs {
		ttl := s.TTL
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		file := CacheFile(u.Dir, s)
		st, err := os.Stat(file)
		if err != nil {
			u.Rep.SetStat(s.Name, SourceStat{Error: "not downloaded yet"})
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			u.Rep.SetStat(s.Name, SourceStat{Error: err.Error()})
			continue
		}
		n := u.load(s, f, st.ModTime().Add(ttl))
		f.Close()
		u.Rep.SetStat(s.Name, SourceStat{Entries: n, Updated: st.ModTime()})
		loaded++
	}
	return loaded
}
