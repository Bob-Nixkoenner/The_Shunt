package speedtest

import (
	"context"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"
)

// Runner measures one step on one route (the daemon starts a process inside
// that route; tests use a fake).
type Runner func(ctx context.Context, route string, s Step) (Measurement, error)

// Options for a run.
type Options struct {
	Routes   []string // what to test; "block" and duplicates are dropped
	Provider string   // default Cloudflare
	Kinds    []string // default ping, down, up
	Rounds   int      // default 3, at most 5
	Bytes    int64    // per download/upload step; default DefaultBytes
	Seed     uint64   // 0: random. Same seed, same order.
	// Pause between two steps (random up to this long; default 1.5 s). Tests set a tiny one.
	MaxPause time.Duration
}

// StepLog is one executed step, in the order it ran.
type StepLog struct {
	Round int         `json:"round"`
	Route string      `json:"route"`
	Kind  string      `json:"kind"`
	M     Measurement `json:"m"`
}

// RouteResult is the outcome for one route: the median of the rounds, and the
// spread, so a short dip in the network does not decide alone.
type RouteResult struct {
	Route       string  `json:"route"`
	State       string  `json:"state"` // ok | partial | failed
	LatencyMs   float64 `json:"latency_ms,omitempty"`
	JitterMs    float64 `json:"jitter_ms,omitempty"`
	DownMbit    float64 `json:"down_mbit,omitempty"`
	DownMin     float64 `json:"down_min,omitempty"`
	DownMax     float64 `json:"down_max,omitempty"`
	UpMbit      float64 `json:"up_mbit,omitempty"`
	UpMin       float64 `json:"up_min,omitempty"`
	UpMax       float64 `json:"up_max,omitempty"`
	IP          string  `json:"ip,omitempty"`
	Loc         string  `json:"loc,omitempty"`
	Error       string  `json:"error,omitempty"`
	Fastest     bool    `json:"fastest,omitempty"`
	Slowest     bool    `json:"slowest,omitempty"`
	Measurement int     `json:"steps"`
}

// Report is the result of a whole run. Seed and Order make it repeatable.
type Report struct {
	Provider string        `json:"provider"`
	Rounds   int           `json:"rounds"`
	Seed     uint64        `json:"seed"`
	Started  time.Time     `json:"started"`
	Order    []StepLog     `json:"order"`
	Routes   []RouteResult `json:"routes"`
}

// Progress is told after every step: how many of how many are done.
type Progress func(done, total int, r *Report)

func (o *Options) normalize() error {
	if o.Provider == "" {
		o.Provider = Cloudflare
	}
	if len(o.Kinds) == 0 {
		o.Kinds = []string{KindPing, KindDown, KindUp}
	}
	if o.Rounds <= 0 {
		o.Rounds = 3
	}
	if o.Rounds > 5 {
		o.Rounds = 5
	}
	if o.MaxPause == 0 {
		o.MaxPause = 1500 * time.Millisecond
	}
	seen := map[string]bool{}
	var routes []string
	for _, r := range o.Routes {
		r = strings.TrimSpace(r)
		if r == "" || r == "block" || seen[r] {
			continue
		}
		seen[r] = true
		routes = append(routes, r)
	}
	if len(routes) == 0 {
		return errors.New("no route to test")
	}
	o.Routes = routes
	kinds := map[string]bool{}
	var ks []string
	for _, k := range o.Kinds {
		if (k == KindPing || k == KindDown || k == KindUp) && !kinds[k] {
			kinds[k] = true
			ks = append(ks, k)
		}
	}
	if len(ks) == 0 {
		return errors.New("no measurement chosen")
	}
	o.Kinds = ks
	for _, k := range ks {
		st := Step{Provider: o.Provider, Kind: k, Bytes: o.Bytes}
		if err := st.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Run measures the routes one after the other (never at the same time: they
// would disturb each other). The order of the routes is shuffled in every
// round, so is the order of the measurement kinds per route, and there is a
// random pause between steps. The result per route is the median over the
// rounds. A route that does not work is shown as failed, never replaced by
// another one.
func Run(ctx context.Context, run Runner, o Options, prog Progress) (*Report, error) {
	if err := o.normalize(); err != nil {
		return nil, err
	}
	seed := o.Seed
	if seed == 0 {
		seed = rand.Uint64() | 1
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	rep := &Report{Provider: o.Provider, Rounds: o.Rounds, Seed: seed, Started: time.Now()}
	total := o.Rounds * len(o.Routes) * len(o.Kinds)
	done := 0
	accs := map[string]*accT{}
	for _, r := range o.Routes {
		accs[r] = &accT{}
	}
	for round := 1; round <= o.Rounds; round++ {
		routes := append([]string(nil), o.Routes...)
		rng.Shuffle(len(routes), func(i, j int) { routes[i], routes[j] = routes[j], routes[i] })
		for _, route := range routes {
			kinds := append([]string(nil), o.Kinds...)
			rng.Shuffle(len(kinds), func(i, j int) { kinds[i], kinds[j] = kinds[j], kinds[i] })
			for _, kind := range kinds {
				if err := ctx.Err(); err != nil {
					rep.Routes = summarize(o.Routes, accs)
					return rep, err
				}
				st := Step{Provider: o.Provider, Kind: kind, Bytes: o.Bytes}
				_ = st.Validate()
				m, err := run(ctx, route, st)
				if err != nil && m.Err == "" {
					m.Err = err.Error()
				}
				accs[route].add(kind, m)
				rep.Order = append(rep.Order, StepLog{Round: round, Route: route, Kind: kind, M: m})
				done++
				rep.Routes = summarize(o.Routes, accs)
				if prog != nil {
					prog(done, total, rep)
				}
				if done < total && o.MaxPause > 0 {
					select {
					case <-time.After(time.Duration(rng.Int64N(int64(o.MaxPause)))):
					case <-ctx.Done():
					}
				}
			}
		}
	}
	rep.Routes = summarize(o.Routes, accs)
	return rep, nil
}

type accT struct {
	lat, jit, down, up []float64
	ip, loc, err       string
	steps, fails       int
}

func (a *accT) add(kind string, m Measurement) {
	a.steps++
	if m.Err != "" {
		a.fails++
		a.err = m.Err
		return
	}
	if m.IP != "" {
		a.ip, a.loc = m.IP, m.Loc
	}
	switch kind {
	case KindPing:
		a.lat = append(a.lat, m.LatencyMs)
		a.jit = append(a.jit, m.JitterMs)
	case KindDown:
		a.down = append(a.down, m.Mbit)
		if m.LatencyMs > 0 {
			a.lat = append(a.lat, m.LatencyMs)
		}
	case KindUp:
		a.up = append(a.up, m.Mbit)
	}
}

func minMax(v []float64) (lo, hi float64) {
	for i, x := range v {
		if i == 0 || x < lo {
			lo = x
		}
		if i == 0 || x > hi {
			hi = x
		}
	}
	return
}

func summarize(routes []string, accs map[string]*accT) []RouteResult {
	var out []RouteResult
	for _, r := range routes {
		a := accs[r]
		rr := RouteResult{Route: r, IP: a.ip, Loc: a.loc, Measurement: a.steps}
		rr.LatencyMs, rr.JitterMs = median(a.lat), median(a.jit)
		rr.DownMbit, rr.UpMbit = median(a.down), median(a.up)
		rr.DownMin, rr.DownMax = minMax(a.down)
		rr.UpMin, rr.UpMax = minMax(a.up)
		switch {
		case a.steps > 0 && a.fails == a.steps:
			rr.State, rr.Error = "failed", a.err
		case a.fails > 0:
			rr.State, rr.Error = "partial", a.err
		default:
			rr.State = "ok"
		}
		out = append(out, rr)
	}
	// mark fastest / slowest download among the routes that have one
	var withDown []int
	for i, r := range out {
		if r.DownMbit > 0 {
			withDown = append(withDown, i)
		}
	}
	if len(withDown) > 1 {
		sort.Slice(withDown, func(i, j int) bool { return out[withDown[i]].DownMbit < out[withDown[j]].DownMbit })
		out[withDown[0]].Slowest = true
		out[withDown[len(withDown)-1]].Fastest = true
	}
	return out
}

// Job runs one test at a time and keeps its state for the UI to poll.
type Job struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	state  JobState
}

// JobState is what the UI shows.
type JobState struct {
	Running bool    `json:"running"`
	Done    int     `json:"done"`
	Total   int     `json:"total"`
	Error   string  `json:"error,omitempty"`
	Report  *Report `json:"report,omitempty"`
}

// State returns a copy of the current state.
func (j *Job) State() JobState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

// Start begins a run in the background; false if one is running already.
func (j *Job) Start(run Runner, o Options) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Running {
		return false, nil
	}
	if err := o.normalize(); err != nil {
		return true, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	j.state = JobState{Running: true, Total: o.Rounds * len(o.Routes) * len(o.Kinds)}
	go func() {
		rep, err := Run(ctx, run, o, func(done, total int, r *Report) {
			j.mu.Lock()
			j.state.Done, j.state.Total = done, total
			cp := *r
			cp.Order = append([]StepLog(nil), r.Order...)
			cp.Routes = append([]RouteResult(nil), r.Routes...)
			j.state.Report = &cp
			j.mu.Unlock()
		})
		j.mu.Lock()
		defer j.mu.Unlock()
		j.state.Running = false
		if rep != nil {
			j.state.Report = rep
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			j.state.Error = err.Error()
		} else if errors.Is(err, context.Canceled) {
			j.state.Error = "cancelled"
		}
	}()
	return true, nil
}

// Cancel stops a running test.
func (j *Job) Cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
}

// WithoutDown drops the routes in down (links that are not connected).
func WithoutDown(routes, down []string) (kept, dropped []string) {
	gone := map[string]bool{}
	for _, d := range down {
		gone[d] = true
	}
	for _, r := range routes {
		if gone[strings.TrimSpace(r)] {
			dropped = append(dropped, r)
		} else {
			kept = append(kept, r)
		}
	}
	return kept, dropped
}

// WithoutTor drops the routes in tor from routes (M-Lab resets connections
// that come through Tor exits, so NDT7 is not offered there). dropped lists
// what was removed.
func WithoutTor(routes []string, tor map[string]bool) (kept, dropped []string) {
	for _, r := range routes {
		if tor[strings.TrimSpace(r)] {
			dropped = append(dropped, r)
		} else {
			kept = append(kept, r)
		}
	}
	return kept, dropped
}
