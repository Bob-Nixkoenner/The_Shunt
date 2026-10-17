package stats

import "time"

// The history keeps traffic per tunnel and DNS blocks in 5-minute slots
// for the last 35 days (enough for "this month"); only slots with
// something in them are stored.
const (
	slotSecs  = 300
	keepSlots = 35 * 24 * 3600 / slotSecs
)

type slot struct {
	T   int64            `json:"t"` // unix start of the slot
	Tun map[string]Bytes `json:"tun,omitempty"`
	DNS int64            `json:"dns,omitempty"`
}

// addSlot adds to the slot of now (b.mu held). Slots arrive in time order,
// so the one we need is the last or a new one.
func (b *Book) addSlot(tunnel string, d Bytes, dns int64, now time.Time) {
	t := now.Unix() / slotSecs * slotSecs
	n := len(b.f.Series)
	if n == 0 || b.f.Series[n-1].T < t {
		b.f.Series = append(b.f.Series, slot{T: t})
		n++
		if n > keepSlots {
			b.f.Series = append([]slot(nil), b.f.Series[n-keepSlots:]...)
			n = keepSlots
		}
	} else if b.f.Series[n-1].T > t { // clock went back: the newest slot takes it
		t = b.f.Series[n-1].T
	}
	sl := &b.f.Series[n-1]
	if tunnel != "" {
		if sl.Tun == nil {
			sl.Tun = map[string]Bytes{}
		}
		v := sl.Tun[tunnel]
		v.add(d)
		sl.Tun[tunnel] = v
	}
	sl.DNS += dns
}

// ObserveDNS feeds the counter of names blocked by the DNS filter (it starts
// at zero with every start of the program; a smaller value means a restart).
func (b *Book) ObserveDNS(total int64, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.lastDNS
	b.lastDNS = total
	if prev < 0 {
		prev = 0 // the counter began with this run: all of it is new
	}
	d := total - prev
	if d < 0 {
		d = total
	}
	if d == 0 {
		return
	}
	b.addSlot("", Bytes{}, d, now)
	b.dirty = true
	if b.path != "" && now.Sub(b.saved) >= SaveEvery {
		b.saveLocked(now)
	}
}

// Point is one step of a history.
type Point struct {
	T   int64 `json:"t"`
	RX  int64 `json:"rx"`
	TX  int64 `json:"tx"`
	DNS int64 `json:"dns"`
}

// History is what the UI draws.
type History struct {
	Range string `json:"range"`
	From  int64  `json:"from"`
	Step  int64  `json:"step"` // seconds per point
	// Points covers From.. now without gaps.
	Points []Point `json:"points"`
	// Tunnels: rx+tx per point for every tunnel (sparklines), aligned to Points.
	Tunnels map[string][]int64 `json:"tunnels"`
	// Totals of the range, and of DNS blocks today / this month.
	RX       int64 `json:"rx"`
	TX       int64 `json:"tx"`
	DNS      int64 `json:"dns"`
	DNSToday int64 `json:"dns_today"`
	DNSMonth int64 `json:"dns_month"`
}

// Ranges the UI offers: window and step.
var ranges = map[string][2]time.Duration{
	"1h":  {time.Hour, 5 * time.Minute},
	"24h": {24 * time.Hour, 30 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 3 * time.Hour},
	"30d": {30 * 24 * time.Hour, 12 * time.Hour},
}

// RangeNames in the order of the UI.
func RangeNames() []string { return []string{"1h", "24h", "7d", "30d"} }

// History summarises the series for a range (unknown names mean 24h).
func (b *Book) History(rng string, now time.Time) History {
	w, ok := ranges[rng]
	if !ok {
		rng, w = "24h", ranges["24h"]
	}
	step := int64(w[1] / time.Second)
	end := (now.Unix()/step + 1) * step // end of the slot we are in
	from := end - int64(w[0]/time.Second)
	n := int((end - from) / step)
	h := History{Range: rng, From: from, Step: step, Points: make([]Point, n), Tunnels: map[string][]int64{}}
	for i := range h.Points {
		h.Points[i].T = from + int64(i)*step
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, sl := range b.f.Series {
		if sl.DNS > 0 {
			if sl.T >= dayStart {
				h.DNSToday += sl.DNS
			}
			if sl.T >= monthStart {
				h.DNSMonth += sl.DNS
			}
		}
		if sl.T < from || sl.T >= end {
			continue
		}
		i := int((sl.T - from) / step)
		p := &h.Points[i]
		p.DNS += sl.DNS
		h.DNS += sl.DNS
		for name, v := range sl.Tun {
			p.RX += v.RX
			p.TX += v.TX
			h.RX += v.RX
			h.TX += v.TX
			if h.Tunnels[name] == nil {
				h.Tunnels[name] = make([]int64, n)
			}
			h.Tunnels[name][i] += v.RX + v.TX
		}
	}
	return h
}
