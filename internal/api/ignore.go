package api

import "github.com/Bob-Nixkoenner/the_shunt/internal/check"

// IgnoreRequest is the body of POST /v1/warnings/ignore: hide the current
// warning with this key (Finding.Key) for "day", "week" or "forever".
// DELETE /v1/warnings/ignore?key=… takes it back, GET /v1/warnings/ignored
// lists what is hidden.
type IgnoreRequest struct {
	Key string `json:"key"`
	For string `json:"for"`
}

// HideWarnings removes what l hides from the findings and notices of st
// (Warnings follow the notices), marks what may be hidden and fills
// Ignored and Hidden. l may be nil (nothing hidden).
func HideWarnings(st *Status, l *check.IgnoreList) {
	var hf, hn []check.Finding
	st.Findings, hf = l.Filter(st.Findings)
	st.Notices, hn = l.Filter(st.Notices)
	if len(hn) > 0 {
		st.Warnings = nil
		if len(st.Notices) > 0 {
			st.Warnings = check.Texts(st.Notices)
		}
	}
	now := map[string]bool{}
	for _, f := range append(hf, hn...) {
		k, _ := check.HideKey(f)
		now[k] = true
	}
	st.Hidden = len(now)
	st.Ignored = l.List()
	for i := range st.Ignored {
		st.Ignored[i].Hiding = now[st.Ignored[i].Key]
	}
}

// FindHideable looks for the warning with key among the findings and
// notices of a status that was not filtered yet.
func FindHideable(st *Status, key string) (check.Finding, bool) {
	for _, fs := range [][]check.Finding{st.Findings, st.Notices} {
		for _, f := range fs {
			if k, ok := check.HideKey(f); ok && k == key {
				return f, true
			}
		}
	}
	return check.Finding{}, false
}
