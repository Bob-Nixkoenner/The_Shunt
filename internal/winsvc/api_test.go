package winsvc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
)

type fakeCore struct {
	panic bool
	pass  time.Duration
}

func (f *fakeCore) Status() string {
	return `{"tunnels":[{"name":"home","type":"wireguard","up":true,"handshake":1700000000,"rx":10,"tx":20,"health":{"state":"ok","handshake_age":5}},{"name":"work","type":"openvpn","via":"home","up":false,"error":"no route","handshake":0,"rx":0,"tx":0,"health":{"state":"down","handshake_age":-1}}],"override":{"panic":true,"pass_left":90},"network":"Büro"}`
}
func (f *fakeCore) History(rng string) string {
	return `{"range":"` + rng + `","from":0,"step":300,"points":[],"tunnels":{},"rx":1,"tx":2,"dns":3,"dns_today":3,"dns_month":3}`
}
func (f *fakeCore) SetPanic(on bool) { f.panic = on }
func (f *fakeCore) ProbeRoute(_ context.Context, route string) ([]byte, error) {
	if route == "nope" {
		return nil, errors.New("unknown route")
	}
	return []byte(`{"ip":"192.0.2.7","resolver":"192.0.2.8"}`), nil
}
func (f *fakeCore) Pass(d time.Duration) time.Time {
	f.pass = d
	return time.Unix(1700000600, 0)
}

func TestAPIOverSocket(t *testing.T) {
	core := &fakeCore{}
	reloaded := 0
	s := &Server{Core: core, Version: "t1",
		Reload: func() error { reloaded++; return nil },
		Config: func() (string, map[string]string) {
			return "tunnel:home", map[string]string{`c:\a\b.exe`: "direct", `c:\a\a.exe`: "block"}
		}}
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go s.Serve(l)

	c := api.NewClient(sock)
	var st api.Status
	if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.DefaultRoute != "tunnel:home" || !st.Panic || st.PassLeft != 90 || st.Version != "t1" || st.Network != "Büro" {
		t.Fatalf("status: %+v", st)
	}
	if len(st.Tunnels) != 2 || !st.Tunnels[0].Up || st.Tunnels[0].Peers[0].RxBytes != 10 || st.Tunnels[1].Via != "home" || st.Tunnels[1].Error != "no route" {
		t.Fatalf("tunnels: %+v", st.Tunnels)
	}
	if got := st.Routes; len(got) != 4 || got[3] != "tunnel:work" {
		t.Fatalf("routes: %v", got)
	}
	if len(st.Rules) != 2 || st.Rules[0] != `c:\a\a.exe -> block` {
		t.Fatalf("rules: %v", st.Rules)
	}

	var h stats.History
	if err := c.Do("GET", "/v1/history?range=7d", nil, &h); err != nil || h.Range != "7d" || h.DNSMonth != 3 {
		t.Fatalf("history: %v %+v", err, h)
	}
	if err := c.Do("POST", "/v1/panic", api.PanicRequest{On: true}, nil); err != nil || !core.panic {
		t.Fatalf("panic: %v %v", err, core.panic)
	}
	if err := c.Do("POST", "/v1/pass", api.PassRequest{Minutes: 5}, nil); err != nil || core.pass != 5*time.Minute {
		t.Fatalf("pass: %v %v", err, core.pass)
	}
	if err := c.Do("POST", "/v1/pass", api.PassRequest{Minutes: 99}, nil); err == nil {
		t.Fatal("99 minutes accepted")
	}
	if err := c.Do("POST", "/v1/reload", nil, nil); err != nil || reloaded != 1 {
		t.Fatalf("reload: %v %d", err, reloaded)
	}
	var pr probe.Result
	if err := c.Do("POST", "/v1/probe", api.ProbeRequest{Route: "direct"}, &pr); err != nil || pr.IP != "192.0.2.7" {
		t.Fatalf("probe: %v %+v", err, pr)
	}
	if err := c.Do("POST", "/v1/probe", api.ProbeRequest{Route: "nope"}, nil); err == nil {
		t.Fatal("unknown route probed")
	}
	if st.Platform != "windows" {
		t.Fatalf("platform %q", st.Platform)
	}
	if err := c.Do("POST", "/v1/restart", nil, nil); err == nil {
		t.Fatal("restart without handler should fail")
	}
}
