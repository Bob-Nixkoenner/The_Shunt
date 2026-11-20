package winsplit

import "testing"

func TestRebindGate(t *testing.T) {
	var g RebindGate
	if g.Poll(true) || g.Poll(true) {
		t.Fatal("rebind without a reason")
	}
	// offline gap: rebind once when the uplink returns, not while it is away
	if g.Poll(false) || g.Poll(false) {
		t.Fatal("rebind while offline")
	}
	if !g.Poll(true) {
		t.Fatal("no rebind after an offline gap")
	}
	if g.Poll(true) {
		t.Fatal("rebind twice for one gap")
	}
	// requested (disguise restarted the adapter), uplink still up at the next poll
	g.Request()
	if !g.Poll(true) {
		t.Fatal("no rebind after a request")
	}
	if g.Poll(true) {
		t.Fatal("rebind twice for one request")
	}
	// requested, uplink goes away, comes back: the request waits, one rebind
	g.Request()
	if g.Poll(false) {
		t.Fatal("rebind while offline with a request pending")
	}
	if !g.Poll(true) {
		t.Fatal("pending request lost while offline")
	}
	if g.Poll(true) {
		t.Fatal("rebind twice (request and gap)")
	}
}
