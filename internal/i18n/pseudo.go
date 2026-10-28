package i18n

import "strings"

// pseudo ("xx") is a test language that is never offered: every known text
// shows up accented and about 40 % longer, so a window shows at a glance
// which texts are translated at all and which are too wide for their place.
const pseudo = "xx"

var accent = map[rune]rune{'a': 'á', 'e': 'é', 'i': 'í', 'o': 'ó', 'u': 'ú', 'A': 'Á', 'E': 'É', 'I': 'Í', 'O': 'Ó', 'U': 'Ú', 'y': 'ý', 'n': 'ñ', 'c': 'ç'}

func pseudoText(s string) string {
	var b strings.Builder
	b.WriteString("[")
	skip := '\x00' // inside {placeholder}, <markup> or &entity; nothing is changed
	n := 0
	for _, r := range s {
		switch {
		case skip == 0 && r == '{':
			skip = '}'
		case skip == 0 && r == '<':
			skip = '>'
		case skip == 0 && r == '&':
			skip = ';'
		case skip != 0 && r == skip:
			b.WriteRune(r)
			skip = 0
			continue
		}
		if a, ok := accent[r]; ok && skip == 0 {
			r = a
		}
		b.WriteRune(r)
		if skip == 0 {
			n++
		}
	}
	b.WriteString(strings.Repeat("·", n*4/10))
	b.WriteString("]")
	return b.String()
}

// pseudoDict covers every text the German catalog knows (the list of
// everything translatable).
func pseudoDict() map[string]string {
	out := map[string]string{}
	if c := catalogs["de"]; c != nil {
		for k := range c.Strings {
			out[k] = pseudoText(k)
		}
	}
	return out
}
