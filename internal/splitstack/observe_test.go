package splitstack

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type slowObs struct {
	mu    sync.Mutex
	block chan struct{}
	conns int
	qs    []string
	ans   map[string][]netip.Addr
}

func (o *slowObs) DNSQuery(app, name, qt string) {
	o.mu.Lock()
	o.qs = append(o.qs, app+"|"+name+"|"+qt)
	o.mu.Unlock()
}
func (o *slowObs) DNSAnswer(name string, a []netip.Addr) {
	o.mu.Lock()
	if o.ans == nil {
		o.ans = map[string][]netip.Addr{}
	}
	o.ans[name] = a
	o.mu.Unlock()
}
func (o *slowObs) NewConn(string, int, netip.AddrPort) {
	if o.block != nil {
		<-o.block
	}
	o.mu.Lock()
	o.conns++
	o.mu.Unlock()
}

func TestObserverNeverBlocksAndDrops(t *testing.T) {
	o := &slowObs{block: make(chan struct{})}
	e := &Engine{o: Options{Observer: o}}
	e.startObserver()
	f := &flow{proto: 6, dst: netip.MustParseAddrPort("203.0.113.1:443"), route: RouteDirect}
	done := make(chan struct{})
	go func() {
		for i := 0; i < obsQueue*3; i++ { // the worker is stuck: must still return
			e.observeConn(f)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observeConn blocked on a slow observer")
	}
	if e.ObserveDropped() < int64(obsQueue) {
		t.Fatalf("dropped %d", e.ObserveDropped())
	}
	close(o.block)
	e.stopObserver()
	e.observeConn(f) // after stop: no panic, no send
}

func TestObserverSkipsBlockedAndDNS(t *testing.T) {
	o := &slowObs{}
	e := &Engine{o: Options{Observer: o}, dns: netip.MustParseAddr(DNSAddr)}
	e.startObserver()
	e.observeConn(&flow{proto: 6, dst: netip.MustParseAddrPort("203.0.113.1:443"), route: RouteBlock})
	e.observeConn(&flow{proto: 17, dst: netip.AddrPortFrom(e.dns, 53), route: RouteDirect})
	e.observeConn(&flow{proto: 6, dst: netip.MustParseAddrPort("203.0.113.1:443"), route: RouteDirect})
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 7}}}
	b, _ := m.Pack()
	e.observeQuery("10123", "example.org.", dns.TypeTXT)
	e.observeAnswer(b)
	e.stopObserver() // drains the queue
	if o.conns != 1 || len(o.qs) != 1 || o.qs[0] != "10123|example.org.|TXT" || len(o.ans["example.org."]) != 1 || o.ans["example.org."][0].String() != "192.0.2.7" {
		t.Fatalf("conns=%d qs=%v ans=%v", o.conns, o.qs, o.ans)
	}
}

func TestObserverNilIsFree(t *testing.T) {
	e := &Engine{}
	e.startObserver()
	e.observeQuery("1", "x.", 1)
	e.observeAnswer(make([]byte, 20))
	e.observeConn(&flow{})
	e.stopObserver()
}
