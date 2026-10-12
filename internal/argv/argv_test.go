package argv

import (
	"reflect"
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
