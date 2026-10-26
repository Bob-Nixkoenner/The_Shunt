package ui

import (
	"encoding/json"
	"net/http"

	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// serveI18N hands the page its language as a script that runs before the
// others (no request to wait for): which language, the choice behind it,
// the languages on offer and, unless it is English, the translations.
func serveI18N(w http.ResponseWriter, r *http.Request) {
	choice := i18n.UserChoice()
	lang := i18n.Detect()
	data := map[string]any{
		"lang":   lang,
		"choice": choice, // "" = automatic
		"auto":   i18n.Resolve(i18n.SystemLanguage()),
		"langs":  i18n.Languages(),
		"dict":   i18n.Dict(lang),
	}
	b, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("window.SHUNT_I18N=" + string(b) + ";\n"))
}
