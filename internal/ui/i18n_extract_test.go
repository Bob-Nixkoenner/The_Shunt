package ui

import (
	"html"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The texts of the page that people read, found in the embedded files: the
// keys of the German catalog must cover them (see i18n_test.go).

var (
	htmlText      = regexp.MustCompile(`>([^<>{}]*[A-Za-z][^<>{}]*)<`)
	htmlAttr      = regexp.MustCompile(`\s(?:title|placeholder|aria-label)="([^"]*[A-Za-z][^"]*)"`)
	htmlBlockOpen = regexp.MustCompile(`<([a-z0-9]+)[^>]*\sdata-i18n="html"[^>]*>`)
	jsLiteral     = regexp.MustCompile("\"((?:[^\"\\\\\\n]|\\\\.)*)\"|`((?:[^`\\\\$]|\\\\.)*)`")
	jsStr         = `"((?:[^"\\\n]|\\.)*)"`
	jsTCall       = regexp.MustCompile(`\bT\(\s*` + jsStr)
	jsTnCall      = regexp.MustCompile(`\bTn\([^,"]*,\s*` + jsStr + `\s*,\s*` + jsStr)
	jsTChoice     = regexp.MustCompile(`\bT\(\s*[^()"?]*\?\s*` + jsStr + `\s*:\s*` + jsStr)
	squashWS      = regexp.MustCompile(`\s+`)
	scriptBlk     = regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>`)
	commentBlk    = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// closeOf: where the </tag> that closes the element opened before pos is.
func closeOf(h, tag string, pos int) int {
	depth, open, closeT := 1, "<"+tag, "</"+tag+">"
	for i := pos; i < len(h); i++ {
		switch {
		case strings.HasPrefix(h[i:], closeT):
			if depth--; depth == 0 {
				return i
			}
		case strings.HasPrefix(h[i:], open) && i+len(open) < len(h) && strings.ContainsRune(" >", rune(h[i+len(open)])):
			depth++
		}
	}
	return len(h)
}

func squash(s string) string { return strings.TrimSpace(squashWS.ReplaceAllString(s, " ")) }

// pageTexts: static texts of index.html (text nodes, attributes and the
// inner HTML of data-i18n="html" blocks).
func pageTexts() []string {
	b, _ := fs.ReadFile(static, "static/index.html")
	h := commentBlk.ReplaceAllString(string(b), "")
	h = scriptBlk.ReplaceAllString(h, "<x></x>")
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = squash(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for {
		loc := htmlBlockOpen.FindStringSubmatchIndex(h)
		if loc == nil {
			break
		}
		tag, inner := h[loc[2]:loc[3]], loc[1]
		end := closeOf(h, tag, inner)
		add(h[inner:end])
		h = h[:loc[0]] + "<x></x>" + h[min(len(h), end+len(tag)+3):]
	}
	// text nodes and attributes are read decoded in the browser ("&" for
	// "&amp;"); the inner HTML of a block is read as the browser writes it
	for _, m := range htmlText.FindAllStringSubmatch(h, -1) {
		add(html.UnescapeString(m[1]))
	}
	for _, m := range htmlAttr.FindAllStringSubmatch(h, -1) {
		add(html.UnescapeString(m[1]))
	}
	sort.Strings(out)
	return out
}

// scriptTexts: strings in the scripts that look like text for people: the
// first argument of T()/Tn() for sure, other literals by their looks.
func scriptTexts() (sure, maybe []string) {
	seenS, seenM := map[string]bool{}, map[string]bool{}
	files, _ := fs.Glob(static, "static/*.js")
	for _, f := range files {
		if strings.HasSuffix(f, "/i18n.js") {
			continue
		}
		b, _ := fs.ReadFile(static, f)
		src := string(b)
		for _, re := range []*regexp.Regexp{jsTCall, jsTnCall, jsTChoice} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				for _, s := range m[1:] {
					s = jsUnescape(s)
					if s != "" && !seenS[s] {
						seenS[s] = true
						sure = append(sure, s)
					}
				}
			}
		}
		for _, m := range jsLiteral.FindAllStringSubmatch(src, -1) {
			s := jsUnescape(m[1] + m[2])
			if looksLikeText(s) && !seenM[s] && !seenS[s] {
				seenM[s] = true
				maybe = append(maybe, s)
			}
		}
	}
	sort.Strings(sure)
	sort.Strings(maybe)
	return
}

var codeish = regexp.MustCompile("^[#.\\[]|^/|^https?:|=>|[{};]|^[a-z][a-z0-9_-]*$|^[a-z]+[A-Z]|\\$\\{|^shunt-|\\.js$|\\.json$|^[A-Z_]+$|^\\s*$")

func looksLikeText(s string) bool {
	if len(s) < 4 || codeish.MatchString(s) || !strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}
	return strings.Contains(s, " ") || (s[0] >= 'A' && s[0] <= 'Z')
}

// jsUnescape turns the source of a JS string literal into the string.
func jsUnescape(s string) string {
	if u, err := strconv.Unquote(`"` + strings.ReplaceAll(s, `\'`, `'`) + `"`); err == nil {
		return u
	}
	return s
}
