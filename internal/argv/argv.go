// Package argv splits and quotes command lines without involving a shell.
package argv

import (
	"fmt"
	"strings"
)

// Split splits a command line into words, honouring single and
// double quotes and backslash escapes. No shell is involved.
func Split(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote rune
	esc := false
	for _, c := range s {
		switch {
		case esc:
			cur.WriteRune(c)
			esc = false
		case c == '\\' && quote != '\'':
			esc, inWord = true, true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case c == '"' || c == '\'':
			quote, inWord = c, true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(c)
			inWord = true
		}
	}
	if quote != 0 || esc {
		return nil, fmt.Errorf("unterminated quote")
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}

// DesktopQuote quotes one argument for an Exec line of a .desktop file
// (freedesktop Desktop Entry spec: reserved characters need double quotes,
// inside them " ` $ \\ are escaped; a literal % is written as %%).
func DesktopQuote(a string) string {
	a = strings.ReplaceAll(a, "%", "%%")
	if a != "" && !strings.ContainsAny(a, " \t\n\"'\\><~|&;$*?#()`=") {
		return a
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	return `"` + r.Replace(a) + `"`
}
