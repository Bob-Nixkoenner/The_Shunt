package ui

import (
	"regexp"
	"sort"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

var placeholder = regexp.MustCompile(`\{\w+\}`)

func placeholders(s string) string {
	p := placeholder.FindAllString(s, -1)
	sort.Strings(p)
	out := ""
	for _, x := range p {
		out += x
	}
	return out
}

// Every language in lang/ must carry the same {placeholders} as the English
// text, or a value would be missing from the sentence.
func TestTranslationsKeepPlaceholders(t *testing.T) {
	for _, l := range i18n.Languages() {
		for k, v := range i18n.Dict(l.Code) {
			if placeholders(k) != placeholders(v) {
				t.Errorf("%s: %q: placeholders differ in %q", l.Code, k, v)
			}
		}
	}
}

// The static texts of the page and every T()/Tn() text in the scripts have a
// German translation (a text that is the same in German is listed with itself
// as its translation). Texts made by other means (plain strings in the
// scripts) are translated while the page runs; I18N_DUMP=1 lists the ones
// that look like text and are not in the catalog yet.
func TestGermanCoversPage(t *testing.T) {
	de := i18n.Dict("de")
	check := func(kind string, texts []string) {
		for _, s := range texts {
			if _, ok := de[s]; !ok {
				t.Errorf("no German for %s %q", kind, s)
			}
		}
	}
	check("page text", pageTexts())
	sure, _ := scriptTexts()
	check("T() text", sure)
}
