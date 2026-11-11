package defense

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var ls []net.Listener
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip("no loopback:", err)
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range ls {
		l.Close()
	}
	return ports
}

// Real sockets, no root: decoys listen on loopback ports, a scan from
// 127.0.0.1 is seen, blocked (hook called) and shows up in the status.
func TestLoopbackDecoyScanBan(t *testing.T) {
	ports := freePorts(t, 8)
	bans := make(chan Ban, 4)
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithListen(LinuxListen(func() string { return "" }, 0)),
		WithBanHooks(func(b Ban) { bans <- b }, nil))
	defer m.Close()
	// one port is taken by someone else: skipped, the rest listens
	taken, err := net.Listen("tcp", net.JoinHostPort("", itoa(ports[7])))
	if err != nil {
		t.Skip(err)
	}
	defer taken.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = ports
	cfg.Features[FeatScan] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	m.SetNetwork("k", ClassTrusted)
	if len(m.Status().Decoys) != 0 {
		t.Fatal("trusted network must not listen")
	}
	m.SetNetwork("k2", ClassPublic)
	if got := len(m.Status().Decoys); got != 7 {
		t.Fatalf("decoys %v (want 7, one port was taken)", m.Status().Decoys)
	}
	for _, p := range ports[:7] {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(p)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	select {
	case b := <-bans:
		if b.Src != "127.0.0.1" || b.Reason != KindScan {
			t.Fatalf("%+v", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan was not blocked")
	}
	m.SetNetwork("k3", ClassManaged)
	if len(m.Status().Decoys) != 0 {
		t.Fatal("managed network must not listen")
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(ports[0])), 300*time.Millisecond); err == nil {
		t.Fatal("decoy still open after leaving the public network")
	}
}
