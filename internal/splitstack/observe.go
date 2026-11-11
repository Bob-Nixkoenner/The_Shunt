package splitstack

import (
	"net/netip"

	"github.com/miekg/dns"
)

// Observer is told what the netstack sees: DNS queries and answers, and new
// connections. It is for watching only (the defense module); it can never
// change a route or block anything.
//
// The calls come from ONE worker goroutine, never from the hot path: the
// hot path only puts a small item into a bounded channel and drops it when
// the channel is full (counted in Engine.ObserveDropped). A slow Observer
// therefore costs events, never throughput.
type Observer interface {
	// DNSQuery: a query of the app (owner ID as Owner returns it, "" =
	// unknown) for name (as asked, with the trailing dot) of type qtype ("A", "TXT" ...).
	DNSQuery(app, name, qtype string)
	// DNSAnswer: the addresses an answer gave for name.
	DNSAnswer(name string, addrs []netip.Addr)
	// NewConn: a new outgoing connection (proto 6 TCP, 17 UDP) of app to dst
	// that was not blocked and is no DNS flow.
	NewConn(app string, proto int, dst netip.AddrPort)
}

const obsQueue = 512

type obsKind uint8

const (
	obsQuery obsKind = iota
	obsAnswer
	obsConn
)

type obsItem struct {
	kind  obsKind
	app   string
	name  string
	qtype uint16
	raw   []byte // obsAnswer: the packed answer (copy)
	proto int
	dst   netip.AddrPort
}

// startObserver starts the worker; e.obs stays nil without an Observer.
func (e *Engine) startObserver() {
	if e.o.Observer == nil {
		return
	}
	e.obs = make(chan obsItem, obsQueue)
	e.obsDone = make(chan struct{})
	go func() {
		defer close(e.obsDone)
		for it := range e.obs {
			e.deliver(it)
		}
	}()
}

// stopObserver ends the worker (Stop: after the stack is closed, so nothing
// sends any more).
func (e *Engine) stopObserver() {
	if e.obs != nil {
		e.obsMu.Lock()
		e.obsClosed = true
		close(e.obs)
		e.obsMu.Unlock()
		<-e.obsDone
	}
}

func (e *Engine) deliver(it obsItem) {
	o := e.o.Observer
	switch it.kind {
	case obsQuery:
		o.DNSQuery(it.app, it.name, dns.TypeToString[it.qtype])
	case obsConn:
		o.NewConn(it.app, it.proto, it.dst)
	case obsAnswer:
		var m dns.Msg
		if m.Unpack(it.raw) != nil || len(m.Question) != 1 {
			return
		}
		var addrs []netip.Addr
		for _, rr := range m.Answer {
			switch r := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(r.A); ok {
					addrs = append(addrs, a.Unmap())
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(r.AAAA); ok {
					addrs = append(addrs, a.Unmap())
				}
			}
		}
		if len(addrs) > 0 {
			o.DNSAnswer(m.Question[0].Name, addrs)
		}
	}
}

// observe is the hot-path entry: never blocks, drops on a full queue.
func (e *Engine) observe(it obsItem) {
	if e.obs == nil {
		return
	}
	e.obsMu.RLock()
	defer e.obsMu.RUnlock()
	if e.obsClosed {
		return
	}
	select {
	case e.obs <- it:
	default:
		e.obsDropped.Add(1)
	}
}

func (e *Engine) observeQuery(app, name string, qtype uint16) {
	if e.obs != nil {
		e.observe(obsItem{kind: obsQuery, app: app, name: name, qtype: qtype})
	}
}

// observeAnswer copies the packed answer (the caller reuses its buffer).
func (e *Engine) observeAnswer(b []byte) {
	if e.obs != nil && len(b) >= 12 {
		e.observe(obsItem{kind: obsAnswer, raw: append([]byte(nil), b...)})
	}
}

func (e *Engine) observeConn(f *flow) {
	if e.obs == nil || f.route == RouteBlock || f.isDNS(e) {
		return
	}
	e.observe(obsItem{kind: obsConn, app: f.app, proto: f.proto, dst: f.dst})
}

// ObserveDropped is how many items the queue dropped because the Observer
// was too slow.
func (e *Engine) ObserveDropped() int64 { return e.obsDropped.Load() }
