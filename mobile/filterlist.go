package mobile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
)

// CheckFilterFile reads a filter list (a downloaded file) the way the DNS
// filter does and says how many names it holds: {"names":N,"truncated":false}.
// An error means the file is not usable as a list (an error page, a wrong
// format). allow: an allowlist, where "@@||name^" lines count too.
func CheckFilterFile(path string, allow bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return checkFilter(f, allow)
}

// CheckFilterText is CheckFilterFile for text typed or pasted into the app.
func CheckFilterText(text string, allow bool) (string, error) {
	return checkFilter(strings.NewReader(text), allow)
}

type reader interface {
	Read(p []byte) (int, error)
}

func checkFilter(r reader, allow bool) (string, error) {
	parse := blocklist.Parse
	if allow {
		parse = blocklist.ParseAllow
	}
	l, err := parse("check", r)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]any{"names": l.Len(), "truncated": l.Truncated})
	return string(b), err
}
