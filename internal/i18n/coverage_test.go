package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	goStr  = `"((?:[^"\\\n]|\\.)*)"`
	goT    = regexp.MustCompile(`\bi18n\.T\(\s*` + goStr)
	goTn   = regexp.MustCompile(`\bi18n\.Tn\([^,]+,\s*` + goStr + `\s*,\s*` + goStr)
	goKV   = regexp.MustCompile(`\{\w+\}`)
	goRoot = "../.."
)

// Every text the Go code gives to i18n.T/Tn has a German translation, with the
// same {placeholders}. A missing one is shown in English, so this is about
// not forgetting; add the text to lang/de.json.
func TestGermanCoversGoTexts(t *testing.T) {
	de := Dict("de")
	seen := map[string]bool{}
	filepath.WalkDir(goRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
			strings.Contains(p, "/internal/i18n/") || strings.Contains(p, "/.git/") {
			return nil
		}
		b, _ := os.ReadFile(p)
		src := string(b)
		var texts []string
		for _, m := range goT.FindAllStringSubmatch(src, -1) {
			texts = append(texts, m[1])
		}
		for _, m := range goTn.FindAllStringSubmatch(src, -1) {
			texts = append(texts, m[1], m[2])
		}
		for _, raw := range texts {
			s, err := strconv.Unquote(`"` + raw + `"`)
			if err != nil || seen[s] {
				continue
			}
			seen[s] = true
			v, ok := de[s]
			if !ok {
				t.Errorf("%s: no German for %q", p, s)
			} else if len(goKV.FindAllString(s, -1)) != len(goKV.FindAllString(v, -1)) {
				t.Errorf("%s: placeholders differ in %q", p, s)
			}
		}
		return nil
	})
	if len(seen) == 0 {
		t.Error("found no texts: is the pattern right?")
	}
}
