package desktopapp

import (
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
)

// TorNotifyAfter: a Tor tunnel needs a while to bootstrap, so "no connection"
// for it is only worth a notification after this long.
const TorNotifyAfter = 30 * time.Second

// TorHold hides "no connection" of Tor tunnels that are younger than a limit.
type TorHold struct{ since map[string]time.Time }

// Filter returns v without the Tor tunnels in Down that have been down for
// less than after. v itself is not changed.
func (h *TorHold) Filter(v View, st *api.Status, now time.Time, after time.Duration) View {
	if h.since == nil {
		h.since = map[string]time.Time{}
	}
	tor := map[string]bool{}
	if st != nil {
		for _, t := range st.Tunnels {
			if t.Bootstrap != nil {
				tor[t.Name] = true
			}
		}
	}
	for n := range h.since {
		if !v.Down[n] || !tor[n] {
			delete(h.since, n)
		}
	}
	down := make(map[string]bool, len(v.Down))
	for n := range v.Down {
		if tor[n] {
			t, ok := h.since[n]
			if !ok {
				h.since[n], t = now, now
			}
			if now.Sub(t) < after {
				continue
			}
		}
		down[n] = true
	}
	v.Down = down
	return v
}
