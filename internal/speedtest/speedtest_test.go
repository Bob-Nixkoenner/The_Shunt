package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A tiny stand-in for the Cloudflare endpoints.
func fakeCF(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(make([]byte, n))
	})
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	})
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fl=1\nip=203.0.113.9\nloc=DE\n")
	})
	srv := httptest.NewServer(mux)
	old := BaseURL
	BaseURL = srv.URL
	t.Cleanup(func() { BaseURL = old; srv.Close() })
}

func TestMeasureCloudflare(t *testing.T) {
	fakeCF(t)
	ctx := context.Background()
	m := Measure(ctx, Step{Provider: Cloudflare, Kind: KindPing})
	if m.Err != "" || m.LatencyMs <= 0 || m.IP != "203.0.113.9" || m.Loc != "DE" {
		t.Errorf("ping: %+v", m)
	}
	m = Measure(ctx, Step{Provider: Cloudflare, Kind: KindDown, Bytes: 2_000_000})
	if m.Err != "" || m.Mbit <= 0 || m.Bytes != 2_000_000 {
		t.Errorf("down: %+v", m)
	}
	m = Measure(ctx, Step{Provider: Cloudflare, Kind: KindUp, Bytes: 2_000_000})
	if m.Err != "" || m.Mbit <= 0 {
		t.Errorf("up: %+v", m)
	}
}

func TestMeasureErrors(t *testing.T) {
	old := BaseURL
	BaseURL = "http://127.0.0.1:1"
	defer func() { BaseURL = old }()
	if m := Measure(context.Background(), Step{Provider: Cloudflare, Kind: KindPing}); m.Err == "" {
		t.Error("a dead server is not an error")
	}
	for _, s := range []Step{{Provider: "x", Kind: KindPing}, {Provider: Cloudflare, Kind: "y"}, {Provider: Cloudflare, Kind: KindDown, Bytes: 5}, {Provider: Cloudflare, Kind: KindDown, Bytes: MaxBytes + 1}} {
		if s.Validate() == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

// fake runner: every route has a speed; "dead" fails; records the order.
type fake struct {
	mu    sync.Mutex
	order []string
}

func (f *fake) run(_ context.Context, route string, s Step) (Measurement, error) {
	f.mu.Lock()
	f.order = append(f.order, route+"/"+s.Kind)
	f.mu.Unlock()
	if route == "tunnel:dead" {
		return Measurement{}, fmt.Errorf("tunnel is down")
	}
	speed := map[string]float64{"direct": 100, "tunnel:vps": 40, "tunnel:tor": 3}[route]
	switch s.Kind {
	case KindPing:
		return Measurement{LatencyMs: 10 + speed/10, JitterMs: 1, IP: "198.51.100." + strconv.Itoa(int(speed))}, nil
	case KindDown:
		return Measurement{Mbit: speed, Bytes: 1}, nil
	}
	return Measurement{Mbit: speed / 2, Bytes: 1}, nil
}

func TestRunOrderAndMedian(t *testing.T) {
	f := &fake{}
	o := Options{Routes: []string{"direct", "tunnel:vps", "tunnel:tor", "tunnel:dead", "block", "direct"}, Rounds: 3, Seed: 42, MaxPause: time.Microsecond}
	rep, err := Run(context.Background(), f.run, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.order) != 3*4*3 { // block and the duplicate are dropped
		t.Fatalf("steps: %d", len(f.order))
	}
	byRoute := map[string]RouteResult{}
	for _, r := range rep.Routes {
		byRoute[r.Route] = r
	}
	if r := byRoute["direct"]; r.State != "ok" || r.DownMbit != 100 || r.UpMbit != 50 || r.LatencyMs != 20 {
		t.Errorf("direct: %+v", r)
	}
	if r := byRoute["tunnel:dead"]; r.State != "failed" || r.Error == "" {
		t.Errorf("dead: %+v", r)
	}
	if !byRoute["direct"].Fastest || !byRoute["tunnel:tor"].Slowest {
		t.Error("fastest/slowest not marked")
	}
	// same seed, same order; another seed, another order
	f2 := &fake{}
	Run(context.Background(), f2.run, o, nil)
	if strings.Join(f.order, ",") != strings.Join(f2.order, ",") {
		t.Error("same seed gave another order")
	}
	f3 := &fake{}
	o.Seed = 7
	Run(context.Background(), f3.run, o, nil)
	if strings.Join(f.order, ",") == strings.Join(f3.order, ",") {
		t.Error("another seed gave the same order")
	}
	// within a round every route is visited once, and the first route differs between rounds sometimes
	if rep.Order[0].Round != 1 || rep.Order[len(rep.Order)-1].Round != 3 {
		t.Error("rounds not recorded")
	}
}

func TestRunShufflesStartRoute(t *testing.T) {
	first := map[string]bool{}
	for seed := uint64(1); seed < 40; seed++ {
		f := &fake{}
		Run(context.Background(), f.run, Options{Routes: []string{"direct", "tunnel:vps", "tunnel:tor"}, Rounds: 1, Seed: seed, MaxPause: time.Microsecond, Kinds: []string{KindPing}}, nil)
		first[strings.Split(f.order[0], "/")[0]] = true
	}
	if len(first) < 3 {
		t.Errorf("the first route is not random: %v", first)
	}
}

func TestRunCancelAndErrors(t *testing.T) {
	if _, err := Run(context.Background(), (&fake{}).run, Options{Routes: []string{"block"}}, nil); err == nil {
		t.Error("only block accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	rep, err := Run(ctx, (&fake{}).run, Options{Routes: []string{"direct"}, MaxPause: time.Microsecond}, func(done, total int, _ *Report) {
		n++
		if done == 2 {
			cancel()
		}
	})
	if err == nil || rep == nil || n != 2 {
		t.Errorf("cancel: err %v rep %v steps %d", err, rep != nil, n)
	}
}

func TestJob(t *testing.T) {
	var j Job
	started, err := j.Start((&fake{}).run, Options{Routes: []string{"direct"}, Rounds: 1, MaxPause: time.Microsecond})
	if !started || err != nil {
		t.Fatal(started, err)
	}
	if again, _ := j.Start((&fake{}).run, Options{Routes: []string{"direct"}}); again && j.State().Running {
		t.Error("two runs at once")
	}
	for i := 0; i < 200 && j.State().Running; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	st := j.State()
	if st.Running || st.Done != 3 || st.Report == nil || st.Report.Routes[0].State != "ok" {
		t.Errorf("state: %+v", st)
	}
}

// A slow upload that runs out of time still gives a speed from what went out.
func TestUploadCutOffKeepsPartial(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond) // about 3 MB/s
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	m := Measure(ctx, Step{Provider: Cloudflare, Kind: KindUp, Bytes: 100_000_000})
	if m.Err != "" || m.Mbit <= 0 || m.Bytes < minPartial || m.Bytes >= 100_000_000 {
		t.Fatalf("partial upload: %+v", m)
	}
}

func TestWithoutTor(t *testing.T) {
	kept, dropped := WithoutTor([]string{"direct", "tunnel:tor1", " tunnel:wg"}, map[string]bool{"tunnel:tor1": true})
	if len(kept) != 2 || len(dropped) != 1 || dropped[0] != "tunnel:tor1" {
		t.Errorf("kept %v dropped %v", kept, dropped)
	}
}

func TestWithoutDown(t *testing.T) {
	kept, dropped := WithoutDown([]string{"direct", "link:wifi", "link:ethernet", "link:mobile"}, []string{"link:ethernet", "link:mobile"})
	if strings.Join(kept, ",") != "direct,link:wifi" || strings.Join(dropped, ",") != "link:ethernet,link:mobile" {
		t.Fatalf("kept %v dropped %v", kept, dropped)
	}
	if k, d := WithoutDown([]string{"direct"}, nil); len(k) != 1 || len(d) != 0 {
		t.Fatalf("%v %v", k, d)
	}
}
