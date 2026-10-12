package argv

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	for in, want := range map[string][]string{
		`firefox -no-remote -P`:        {"firefox", "-no-remote", "-P"},
		`app "with space" 'single $x'`: {"app", "with space", "single $x"},
		`a\ b "c\"d"`:                  {"a b", `c"d`},
		`x ""`:                         {"x", ""},
	} {
		got, err := Split(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q %v", in, got, err)
		}
	}
	if _, err := Split(`unterminated "quote`); err == nil {
		t.Error("expected error")
	}
}

func TestDesktopQuote(t *testing.T) {
	for in, want := range map[string]string{
		"-P":           "-P",
		"Social Media": `"Social Media"`,
		`a"b`:          `"a\"b"`,
		"100%":         "100%%",
		"$HOME":        `"\$HOME"`,
		"--x=1":        `"--x=1"`,
	} {
		if got := DesktopQuote(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func FuzzSplit(f *testing.F) {
	f.Add(`firefox --new-instance -P "Social Media"`)
	f.Add(`a\ b 'c d' "e\"f"`)
	f.Fuzz(func(t *testing.T, s string) {
		words, err := Split(s)
		if err != nil {
			return
		}
		// quoting for a .desktop Exec line must split back to the same words
		// (field codes aside, which DesktopQuote doubles)
		var q []string
		for _, w := range words {
			q = append(q, DesktopQuote(w))
		}
		back, err := Split(strings.Join(q, " "))
		if err != nil {
			t.Fatalf("re-split failed: %v", err)
		}
		for i := range back {
			back[i] = strings.ReplaceAll(back[i], "%%", "%")
		}
		if !reflect.DeepEqual(back, words) && len(words) > 0 {
			t.Fatalf("%q -> %q -> %q", words, q, back)
		}
	})
}
