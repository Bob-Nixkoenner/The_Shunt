package defense

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func verifyManager(t *testing.T, mut func(*Config)) (*Manager, *fakeClock) {
	t.Helper()
	m, clk := newTestManager(t, &portMap{real: map[int]int{}}, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Features[FeatDecoy] = Feature{} // no listeners needed here
	cfg.Features[FeatScan] = Feature{Watch: true, Block: true}
	cfg.Features[FeatBrute] = Feature{Watch: true, Block: true}
	cfg.Features[FeatReputation] = Feature{Watch: true, Block: true}
	if mut != nil {
		mut(&cfg)
	}
	m.Configure(cfg)
	return m, clk
}

func synScan(m *Manager, src netip.Addr) {
	for p := 1; p <= 12; p++ {
		m.ObserveState(src, p, "tcp", StateS0) // what the packet log sees: lone SYNs
	}
}

func lastOf(m *Manager, k Kind) (Event, bool) {
	evs := m.Events(0).Events
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == k {
			return evs[i], true
		}
	}
	return Event{}, false
}

// A scan made of SYNs alone (the source may be forged) is reported but not
// blocked. The first finished handshake with a decoy carries the block out.
func TestBanWaitsForHandshake(t *testing.T) {
	m, _ := verifyManager(t, nil)
	src := netip.MustParseAddr("203.0.113.7")
	synScan(m, src)
	ev, ok := lastOf(m, KindScan)
	if !ok || !strings.Contains(ev.Detail, "block=waits_for_handshake") {
		t.Fatalf("scan event: %+v", ev)
	}
	if n := len(m.Status().Bans); n != 0 {
		t.Fatalf("blocked on SYNs alone: %d", n)
	}
	m.decoyHit(Hit{Src: src, Port: 80, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})
	bans := m.Status().Bans
	if len(bans) != 1 || bans[0].Src != "203.0.113.7" || bans[0].Reason != KindScan {
		t.Fatalf("after the handshake: %+v", bans)
	}
	if ev, _ := lastOf(m, KindBan); !strings.Contains(ev.Detail, "confirmed=handshake") {
		t.Fatalf("ban event: %+v", ev)
	}
	if _, p := m.ver.sizes(); p != 0 {
		t.Fatalf("pending left: %d", p)
	}
}

// A source that already proved its address is blocked at once.
func TestBanAtOnceWhenConfirmed(t *testing.T) {
	m, _ := verifyManager(t, nil)
	src := netip.MustParseAddr("2001:db8::7")
	m.decoyHit(Hit{Src: src, Port: 80, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})
	if len(m.Status().Bans) != 0 {
		t.Fatal("one decoy hit is no reason to block")
	}
	synScan(m, src)
	if bans := m.Status().Bans; len(bans) != 1 || bans[0].Src != "2001:db8::7" {
		t.Fatalf("%+v", bans)
	}
	if ev, _ := lastOf(m, KindScan); strings.Contains(ev.Detail, "waits_for_handshake") {
		t.Fatalf("scan event says it waits: %+v", ev)
	}
}

// The waiting block and the proof both expire.
func TestBanWaitExpires(t *testing.T) {
	m, clk := verifyManager(t, nil)
	src := netip.MustParseAddr("203.0.113.8")
	synScan(m, src)
	clk.Add(pendingTTL + time.Minute)
	m.decoyHit(Hit{Src: src, Port: 80, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})
	if n := len(m.Status().Bans); n != 0 {
		t.Fatalf("an expired finding was carried out: %d", n)
	}
	// proof expired: a new scan waits again
	clk.Add(verifiedTTL + time.Minute)
	synScan(m, src)
	if n := len(m.Status().Bans); n != 0 {
		t.Fatalf("old proof still counted: %d", n)
	}
	if !m.ver.waiting(src, m.now()) {
		t.Fatal("new finding does not wait")
	}
}

// ban_unverified = true restores blocking on packets alone; reputation hits
// and manual blocks are never held back.
func TestBanNotHeldBack(t *testing.T) {
	m, _ := verifyManager(t, func(c *Config) { c.BanUnverified = true })
	synScan(m, netip.MustParseAddr("203.0.113.9"))
	if n := len(m.Status().Bans); n != 1 {
		t.Fatalf("ban_unverified: %d bans", n)
	}

	m2, _ := verifyManager(t, nil)
	m2.rep.SetList("feodo", []netip.Prefix{netip.MustParsePrefix("198.51.100.5/32")}, time.Time{})
	m2.ObserveState(netip.MustParseAddr("198.51.100.5"), 22, "tcp", StateS0)
	if bans := m2.Status().Bans; len(bans) != 1 || bans[0].Reason != KindReputation {
		t.Fatalf("reputation hit held back: %+v", bans)
	}
	if err := m2.Ban("203.0.113.10"); err != nil || len(m2.Status().Bans) != 2 {
		t.Fatalf("manual block: %v", err)
	}
}

// A flood of forged sources cannot grow the tables.
func TestVerifierCaps(t *testing.T) {
	var v verifier
	now := time.Now()
	for i := 0; i < verifyMax+2000; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		v.hold(a, KindScan, now)
		v.confirm(netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}), now)
	}
	ver, pend := v.sizes()
	if ver > verifyMax || pend > verifyMax {
		t.Fatalf("verified %d pending %d", ver, pend)
	}
	v.prune(now.Add(verifiedTTL + time.Second))
	if ver, pend = v.sizes(); ver != 0 || pend != 0 {
		t.Fatalf("after prune: %d %d", ver, pend)
	}
}

// Lab H04, second part (cannot be driven in the lab): the address of a
// tunnel endpoint is never blocked automatically, even when it proved
// itself with a finished handshake at a decoy and then gives every reason.
// The daemon puts the endpoints on the automatic never-block list
// (Daemon.defenseTunnelPeers -> SetNever); a forged or real attack "from the
// VPN server" must not cut the tunnel.
func TestConfirmedTunnelEndpointNotBanned(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	hit := func(m *Manager, src netip.Addr) {
		m.decoyHit(Hit{Src: src, Port: 80, Kind: KindDecoyHit, Sev: SevMedium, Detail: "tcp connect"})
	}
	noBan := func(t *testing.T, m *Manager, what string) {
		t.Helper()
		if bans := m.Status().Bans; len(bans) != 0 {
			t.Fatalf("%s: tunnel endpoint blocked: %+v", what, bans)
		}
		if ev, ok := lastOf(m, KindBan); ok {
			t.Fatalf("%s: ban event: %+v", what, ev)
		}
		if _, p := m.ver.sizes(); p != 0 {
			t.Fatalf("%s: a block is waiting for the endpoint (%d pending)", what, p)
		}
	}

	t.Run("confirmed, then scan", func(t *testing.T) {
		m, _ := verifyManager(t, nil)
		m.SetNever([]netip.Prefix{netip.PrefixFrom(endpoint, 32)})
		hit(m, endpoint)
		if !m.ver.confirmed(endpoint, m.now()) {
			t.Fatal("the handshake did not confirm the endpoint: the test would prove nothing")
		}
		if _, ok := lastOf(m, KindDecoyHit); !ok {
			t.Fatal("the decoy hit of the endpoint must still be shown")
		}
		synScan(m, endpoint)
		for p := 1; p <= 40; p++ { // and a storm of refused connections
			m.ObserveState(endpoint, 22, "tcp", StateREJ)
		}
		noBan(t, m, "scan and failed connections after the handshake")
		// control: the same from another confirmed address is blocked
		other := netip.MustParseAddr("203.0.113.10")
		hit(m, other)
		synScan(m, other)
		if bans := m.Status().Bans; len(bans) != 1 || bans[0].Src != other.String() {
			t.Fatalf("control source not blocked, the test proves nothing: %+v", bans)
		}
	})

	t.Run("scan held, address becomes an endpoint, then handshake", func(t *testing.T) {
		m, _ := verifyManager(t, nil)
		synScan(m, endpoint) // not an endpoint yet: the block waits
		if !m.ver.waiting(endpoint, m.now()) {
			t.Fatal("no waiting block: the test would prove nothing")
		}
		m.SetNever([]netip.Prefix{netip.PrefixFrom(endpoint, 32)}) // a tunnel to this address comes up
		hit(m, endpoint)                                           // the handshake would now carry the block out
		if bans := m.Status().Bans; len(bans) != 0 {
			t.Fatalf("waiting block carried out against a tunnel endpoint: %+v", bans)
		}
	})

	t.Run("bad list", func(t *testing.T) {
		m, _ := verifyManager(t, nil)
		m.SetNever([]netip.Prefix{netip.PrefixFrom(endpoint, 32)})
		m.rep.SetList("feodo", []netip.Prefix{netip.PrefixFrom(endpoint, 32), netip.MustParsePrefix("198.51.100.5/32")}, time.Time{})
		hit(m, endpoint)
		m.ObserveState(endpoint, 22, "tcp", StateS0)
		if _, ok := lastOf(m, KindReputation); !ok {
			t.Fatal("the list hit must still be reported")
		}
		noBan(t, m, "address on a bad list")
		m.ObserveState(netip.MustParseAddr("198.51.100.5"), 22, "tcp", StateS0)
		if bans := m.Status().Bans; len(bans) != 1 || bans[0].Src != "198.51.100.5" {
			t.Fatalf("control source not blocked: %+v", bans)
		}
	})

	t.Run("ban_unverified", func(t *testing.T) {
		m, _ := verifyManager(t, func(c *Config) { c.BanUnverified = true })
		m.SetNever([]netip.Prefix{netip.PrefixFrom(endpoint, 32)})
		hit(m, endpoint)
		synScan(m, endpoint)
		noBan(t, m, "blocking without a handshake")
	})

	t.Run("range block next to the endpoint", func(t *testing.T) {
		m, _ := verifyManager(t, nil)
		m.SetNever([]netip.Prefix{netip.PrefixFrom(endpoint, 32)})
		m.SetExposure(Exposure{V4: true, Inbound: "open"})
		// enough confirmed scanners from the endpoint's own range to make
		// the block a range block
		for i := 0; i < RangeBanSources+2; i++ {
			src := netip.AddrFrom4([4]byte{203, 0, 113, byte(100 + i)})
			hit(m, src)
			synScan(m, src)
		}
		bans := m.Status().Bans
		if len(bans) == 0 {
			t.Fatal("neighbours not blocked: the test would prove nothing")
		}
		for _, b := range bans {
			if p, err := netip.ParsePrefix(b.Src); err == nil && p.Contains(endpoint) {
				t.Fatalf("a range block swallowed the tunnel endpoint: %+v", b)
			}
			if b.Src == endpoint.String() {
				t.Fatalf("tunnel endpoint blocked: %+v", b)
			}
		}
	})
}
