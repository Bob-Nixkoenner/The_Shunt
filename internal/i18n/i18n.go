// Package i18n puts The Shunt's texts into the user's language.
//
// The English text is the key: i18n.T("Everything else goes") finds its
// translation in lang/<code>.json and falls back to the English text, so a
// missing translation is never visible as a key. A language is one file;
// dropping lang/fr.json in is all it takes to offer French.
//
// Which language: SHUNT_LANG, else the choice in the user's ui-state file
// ("shunt-lang", set under View), else the operating system's language. Only
// text for people is translated: logs, JSON output and config keys stay as
// they are.
package i18n

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed lang/*.json
var langFS embed.FS

// Source is the language the code is written in.
const Source = "en"

// Language is one entry of the language list.
type Language struct {
	Code string `json:"code"`
	Name string `json:"name"` // in its own language, e.g. "Deutsch"
}

type catalog struct {
	Name    string            `json:"name"`
	Strings map[string]string `json:"strings"`
}

var (
	mu       sync.Mutex
	catalogs map[string]*catalog // by code, loaded once
	current  string              // the language in use ("" = not decided yet)
	forced   bool                // Set was called: stay with it
	checked  time.Time           // when current was last detected
)

// recheckEvery: a program that runs for days (the tray) follows the choice
// made under View without a restart.
const recheckEvery = 3 * time.Second

func load() {
	if catalogs != nil {
		return
	}
	catalogs = map[string]*catalog{}
	ents, _ := langFS.ReadDir("lang")
	for _, e := range ents {
		code := strings.TrimSuffix(e.Name(), ".json")
		if code == e.Name() {
			continue
		}
		b, err := langFS.ReadFile("lang/" + e.Name())
		if err != nil {
			continue
		}
		var c catalog
		if json.Unmarshal(b, &c) == nil && c.Strings != nil {
			catalogs[code] = &c
		}
	}
}

// Languages lists the languages to offer: English first, then the others by code.
func Languages() []Language {
	mu.Lock()
	defer mu.Unlock()
	load()
	out := []Language{{Source, "English"}}
	var codes []string
	for code := range catalogs {
		if code != Source && code != pseudo {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	for _, code := range codes {
		name := catalogs[code].Name
		if name == "" {
			name = code
		}
		out = append(out, Language{code, name})
	}
	return out
}

// Resolve maps what a system or a user says ("de_DE.UTF-8", "pt-BR", "de")
// to a language we have: the full code first ("pt-br"), then its language
// ("pt"), else English.
func Resolve(want string) string {
	mu.Lock()
	defer mu.Unlock()
	load()
	return resolve(want)
}

func resolve(want string) string {
	w := strings.ToLower(want)
	if i := strings.IndexAny(w, ".@"); i >= 0 {
		w = w[:i]
	}
	w = strings.ReplaceAll(w, "_", "-")
	if w == pseudo {
		return pseudo // the test language: only by asking for it
	}
	for w != "" {
		if _, ok := catalogs[w]; ok || w == Source {
			return w
		}
		i := strings.LastIndex(w, "-")
		if i < 0 {
			break
		}
		w = w[:i]
	}
	return Source
}

// Detect decides the language: SHUNT_LANG, the user's choice, the system.
func Detect() string {
	for _, c := range []string{os.Getenv("SHUNT_LANG"), UserChoice()} {
		if c != "" && c != "auto" {
			return Resolve(c)
		}
	}
	return Resolve(SystemLanguage())
}

// SystemLanguage is the language of the operating system (not resolved).
func SystemLanguage() string { return osLanguage() }

// UserChoice reads the language picked under View from the user's ui-state
// file ("" = automatic). The path is the one internal/ui keeps it at.
func UserChoice() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "shunt", "ui-state.json"))
	if err != nil {
		return ""
	}
	var st map[string]string
	if json.Unmarshal(b, &st) != nil {
		return ""
	}
	return st["shunt-lang"]
}

// Set fixes the language for this process ("" = detect again, and keep
// following the user's choice).
func Set(code string) {
	mu.Lock()
	defer mu.Unlock()
	load()
	if code == "" {
		current, forced = "", false
		return
	}
	current, forced = resolve(code), true
}

// Current is the language in use.
func Current() string {
	mu.Lock()
	defer mu.Unlock()
	load()
	if !forced && (current == "" || time.Since(checked) > recheckEvery) {
		current, checked = resolve(detectLocked()), time.Now()
	}
	return current
}

func detectLocked() string {
	for _, c := range []string{os.Getenv("SHUNT_LANG"), UserChoice()} {
		if c != "" && c != "auto" {
			return c
		}
	}
	return SystemLanguage()
}

// Dict returns the translations of a language for the web page (nil for English).
func Dict(code string) map[string]string {
	mu.Lock()
	defer mu.Unlock()
	load()
	if code == pseudo {
		return pseudoDict()
	}
	if c := catalogs[code]; c != nil && code != Source {
		return c.Strings
	}
	return nil
}

// T translates msg; placeholders {name} are filled from the key/value
// pairs: T("DNS for {route} does not work", "route", r).
func T(msg string, kv ...any) string {
	return fill(lookup(Current(), msg), kv)
}

// Tn picks one or many by n and fills {n}: Tn(2, "{n} rule", "{n} rules").
func Tn(n int, one, many string, kv ...any) string {
	m := many
	if n == 1 {
		m = one
	}
	return fill(lookup(Current(), m), append([]any{"n", n}, kv...))
}

func lookup(code, msg string) string {
	if code == Source {
		return msg
	}
	mu.Lock()
	defer mu.Unlock()
	if code == pseudo {
		return pseudoText(msg)
	}
	if c := catalogs[code]; c != nil {
		if s, ok := c.Strings[msg]; ok && s != "" {
			return s
		}
	}
	return msg
}

// Fill puts the values into the {placeholders} of msg without translating it
// (the English text for logs).
func Fill(msg string, kv ...any) string { return fill(msg, kv) }

func fill(s string, kv []any) string {
	if len(kv) < 2 || !strings.Contains(s, "{") {
		return s
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		s = strings.ReplaceAll(s, "{"+k+"}", toString(kv[i+1]))
	}
	return s
}
