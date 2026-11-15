package windefense

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
)

// fakeFW records what the runner asks of the WFP filters.
type fakeFW struct {
	mu       sync.Mutex
	never    []netip.Prefix
	bans     map[netip.Prefix]bool
	clears   int
	failAdd  bool
	failNevr bool
}

func (f *fakeFW) SetNever(p []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNevr {
		return errors.New("engine says no")
	}
	f.never = append([]netip.Prefix(nil), p...)
	return nil
}

func (f *fakeFW) Add(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdd {
		return errors.New("engine says no")
	}
	if f.bans == nil {
		f.bans = map[netip.Prefix]bool{}
	}
	f.bans[p] = true
	return nil
}

func (f *fakeFW) Remove(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bans, p)
	return nil
}

func (f *fakeFW) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = nil
	f.clears++
	return nil
}

func (f *fakeFW) has(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bans[netip.MustParsePrefix(s)]
}

func (f *fakeFW) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bans)
}

func (f *fakeFW) neverHas(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.never {
		if p.String() == s {
			return true
		}
	}
	return false
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func onConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	c, err := config.Parse("[daemon]\ndefault_route = \"direct\"\n[defense]\nenabled = true\n" + extra)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var lab = netdetect.Info{Iface: "Ethernet", SSID: "x", GatewayIP: "192.0.2.1"}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal(what)
}

// The gateway, the DNS servers and the tunnel endpoints are never blocked:
// the manager refuses them and the firewall gets them as permits.
func TestGatewayNeverBanned(t *testing.T) {
	fw := &fakeFW{}
	r := New(t.TempDir(), quiet(), nil, nil)
	defer r.Close()
	r.UseFirewall(fw)
	r.Apply(onConfig(t, ""))
	r.Network(lab)
	r.SetNever(NeverDNS, []netip.Prefix{netip.MustParsePrefix("192.0.2.53/32")})
	r.SetNever(NeverTun, TunnelPeers(context.Background(), []string{"198.51.100.9:51820"}, nil))
	if !r.CanBlock() {
		t.Fatal("firewall with a never-list must block")
	}
	for _, s := range []string{"192.0.2.1/32", "192.0.2.53/32", "198.51.100.9/32"} {
		if !fw.neverHas(s) {
			t.Errorf("%s not on the firewall never-list %v", s, fw.never)
		}
	}
	for _, a := range []string{"192.0.2.1", "192.0.2.53", "198.51.100.9"} {
		if err := r.Ban(a); !errors.Is(err, defense.ErrNeverBan) {
			t.Errorf("ban %s: %v", a, err)
		}
	}
	if fw.count() != 0 {
		t.Fatalf("firewall got a ban: %v", fw.bans)
	}
	if err := r.Ban("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if !fw.has("203.0.113.7/32") {
		t.Fatal("ban not in the firewall")
	}
	if err := r.Ban("127.0.0.1"); err == nil {
		waitFor(t, "loopback ban not dropped", func() bool { return len(r.M.Status().Bans) == 1 })
	}
	if fw.has("127.0.0.1/32") {
		t.Fatal("loopback in the firewall")
	}
	r.M.Unban("203.0.113.7")
	if fw.count() != 0 {
		t.Fatal("unban did not reach the firewall")
	}
}

// Without the gateway on the never-list (network not known yet) or without
// firewall, nothing is blocked and the API says so.
func TestNoBlockWithoutGatewayOrFirewall(t *testing.T) {
	r := New(t.TempDir(), quiet(), nil, nil)
	defer r.Close()
	r.Apply(onConfig(t, ""))
	r.Network(lab)
	if r.CanBlock() || !errors.Is(r.Ban("203.0.113.7"), ErrNoBlocking) {
		t.Fatal("no firewall: no block")
	}
	if st := r.Status(); st.Config.Features[defense.FeatScan].Block {
		t.Error("block switch on without firewall")
	}
	r2 := New(t.TempDir(), quiet(), nil, nil)
	defer r2.Close()
	fw := &fakeFW{}
	r2.UseFirewall(fw)
	r2.Apply(onConfig(t, ""))
	if r2.CanBlock() {
		t.Fatal("gateway unknown: no block")
	}
	r2.Network(lab)
	if !r2.CanBlock() {
		t.Fatal("gateway known: block")
	}
}

// A ban the firewall refuses is dropped (no ban + log), never kept as if
// it held.
func TestFirewallErrorDropsBan(t *testing.T) {
	fw := &fakeFW{failAdd: true}
	r := New(t.TempDir(), quiet(), nil, nil)
	defer r.Close()
	r.UseFirewall(fw)
	r.Apply(onConfig(t, ""))
	r.Network(lab)
	if err := r.Ban("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "refused ban still listed", func() bool { return len(r.M.Status().Bans) == 0 })
	ev := r.M.Events(0).Events
	found := false
	for _, e := range ev {
		found = found || (e.Kind == defense.KindUnban && e.Detail == "not_enforced")
	}
	if !found {
		t.Errorf("no not_enforced event: %+v", ev)
	}
}

// A never-list the firewall refuses switches blocking off and lifts what
// was blocked.
func TestNeverFailureLiftsBans(t *testing.T) {
	fw := &fakeFW{}
	r := New(t.TempDir(), quiet(), nil, nil)
	defer r.Close()
	r.UseFirewall(fw)
	r.Apply(onConfig(t, ""))
	r.Network(lab)
	if err := r.Ban("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	fw.mu.Lock()
	fw.failNevr = true
	fw.mu.Unlock()
	r.SetNever(NeverDNS, []netip.Prefix{netip.MustParsePrefix("192.0.2.53/32")})
	if r.CanBlock() {
		t.Fatal("never-list failed: blocking must be off")
	}
	if fw.count() != 0 || len(r.M.Status().Bans) != 0 {
		t.Fatal("bans must be lifted")
	}
}

// Emergency switch: defense off, LiftAll and a stop leave nothing blocked.
func TestEmergencySwitch(t *testing.T) {
	fw := &fakeFW{}
	r := New(t.TempDir(), quiet(), nil, nil)
	r.UseFirewall(fw)
	r.Apply(onConfig(t, ""))
	r.Network(lab)
	for _, a := range []string{"203.0.113.7", "203.0.113.8"} {
		if err := r.Ban(a); err != nil {
			t.Fatal(err)
		}
	}
	if fw.count() != 2 {
		t.Fatal(fw.bans)
	}
	off, _ := config.Parse("[daemon]\ndefault_route = \"direct\"\n[defense]\nenabled = false\n")
	r.Apply(off)
	if fw.count() != 0 || len(r.M.Status().Bans) != 0 {
		t.Fatal("defense off must lift every ban")
	}
	r.Apply(onConfig(t, ""))
	if err := r.Ban("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	r.LiftAll("manual")
	if fw.count() != 0 || len(r.M.Status().Bans) != 0 {
		t.Fatal("LiftAll")
	}
	if err := r.Ban("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	n := fw.clears
	r.Close()
	if fw.count() != 0 || fw.clears <= n {
		t.Fatal("stop must lift every ban")
	}
}

// Decoys listen on the given address in unknown networks and not in safe
// ones; a hit is reported.
func TestDecoysOnUplink(t *testing.T) {
	var ports []int
	for i := 0; i < 2; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
		l.Close()
	}
	lo := netip.MustParseAddr("127.0.0.1")
	listen := defense.AddrListen(func() netip.Addr { return lo }, nil, net.ListenConfig{})
	r := New(t.TempDir(), quiet(), nil, listen)
	defer r.Close()
	r.Apply(onConfig(t, fmt.Sprintf("decoy_ports = [%d, %d]\n", ports[0], ports[1])+`
[[network]]
name = "home"
ssid = ["Home"]
default_route = "direct"
class = "safe"
`))
	r.Network(lab)
	if got := r.M.DecoyPorts(); len(got) != 2 {
		t.Fatalf("decoys %v", got)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitFor(t, "no decoy hit", func() bool { return r.M.Status().Counts[defense.KindDecoyHit] > 0 })
	home := lab
	home.SSID = "Home"
	r.Network(home)
	if got := r.M.DecoyPorts(); len(got) != 0 {
		t.Fatalf("safe network must not listen: %v", got)
	}
}

// TunnelPeers keeps addresses, resolves names and drops junk.
func TestTunnelPeers(t *testing.T) {
	lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
		if h == "vpn.example.net" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}, nil
		}
		return nil, errors.New("nx")
	}
	got := TunnelPeers(context.Background(), []string{"198.51.100.9:51820", "[2001:db8::1]:443", "vpn.example.net:51820",
		"gone.example.net:1", "127.0.0.1:9050", "relay xyz", "", "198.51.100.9"}, lookup)
	want := []string{"198.51.100.9/32", "203.0.113.5/32", "2001:db8::1/128", "2001:db8::5/128"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: %s want %s", i, got[i], want[i])
		}
	}
}
