//go:build !windows

package i18n

import (
	"os"
	"strings"
)

// osLanguage: the first of LANGUAGE (a list, first entry), LC_ALL,
// LC_MESSAGES, LANG that names a language; "C" and "POSIX" say none.
func osLanguage() string {
	for _, k := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		v := os.Getenv(k)
		if i := strings.Index(v, ":"); i >= 0 {
			v = v[:i]
		}
		if v != "" && v != "C" && v != "POSIX" {
			return v
		}
	}
	return ""
}
