package defense

import (
	"net/netip"
	"sync"
	"time"
)

// Ban spoofing, second half. A scan or brute-force finding can be built
// from SYN packets alone, and their source address can be forged. So an
// automatic block needs proof that the source can receive our answers: it
// finished a TCP handshake with a decoy (the accept returned, which needs
// the ACK for our SYN-ACK). Until then a finding is reported and the block
// waits; the first real connection to a decoy carries it out.
//
// Limits: an attacker who can read our SYN-ACK (same open Wi-Fi, on the
// path) can still finish a handshake under a forged address. Reputation
// hits and manual blocks are not held back (see maybeBan).

const (
	verifiedTTL = 30 * time.Minute // a handshake counts this long
	pendingTTL  = 10 * time.Minute // a finding waits this long for one
	verifyMax   = 4096             // entries kept per table
)

type pendingBan struct {
	reason Kind
	at     time.Time
}

// verifier remembers which sources proved their address and which blocks
// wait for that proof.
type verifier struct {
	mu       sync.Mutex
	verified map[netip.Addr]time.Time
	pending  map[netip.Addr]pendingBan
}

// confirm notes a finished handshake from a. It returns the block that
// waited for it, if any.
func (v *verifier) confirm(a netip.Addr, now time.Time) (Kind, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verified == nil {
		v.verified = map[netip.Addr]time.Time{}
	}
	if _, has := v.verified[a]; !has && len(v.verified) >= verifyMax {
		for k, t := range v.verified {
			if now.Sub(t) > verifiedTTL {
				delete(v.verified, k)
			}
		}
		if len(v.verified) >= verifyMax { // all fresh: drop any one
			for k := range v.verified {
				delete(v.verified, k)
				break
			}
		}
	}
	v.verified[a] = now
	p, ok := v.pending[a]
	if !ok {
		return "", false
	}
	delete(v.pending, a)
	if now.Sub(p.at) > pendingTTL {
		return "", false
	}
	return p.reason, true
}

// confirmed reports whether a finished a handshake recently.
func (v *verifier) confirmed(a netip.Addr, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.verified[a]
	return ok && now.Sub(t) <= verifiedTTL
}

// hold remembers a block that waits for a handshake. A full table first
// drops what expired; if it is still full the new entry is not kept (a
// flood of forged sources must not grow memory).
func (v *verifier) hold(a netip.Addr, reason Kind, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.pending == nil {
		v.pending = map[netip.Addr]pendingBan{}
	}
	if _, has := v.pending[a]; !has && len(v.pending) >= verifyMax {
		for k, p := range v.pending {
			if now.Sub(p.at) > pendingTTL {
				delete(v.pending, k)
			}
		}
		if len(v.pending) >= verifyMax {
			return
		}
	}
	v.pending[a] = pendingBan{reason, now}
}

// waiting reports whether a block for a waits for a handshake.
func (v *verifier) waiting(a netip.Addr, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	p, ok := v.pending[a]
	return ok && now.Sub(p.at) <= pendingTTL
}

// prune drops expired entries (housekeeping tick).
func (v *verifier) prune(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, t := range v.verified {
		if now.Sub(t) > verifiedTTL {
			delete(v.verified, k)
		}
	}
	for k, p := range v.pending {
		if now.Sub(p.at) > pendingTTL {
			delete(v.pending, k)
		}
	}
}

// sizes is for tests and the status.
func (v *verifier) sizes() (verified, pending int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.verified), len(v.pending)
}
