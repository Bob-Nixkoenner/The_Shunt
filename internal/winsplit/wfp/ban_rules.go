package wfp

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Bans of the defense module (Windows counterpart of the Linux nft table
// shunt_defense): every packet from a blocked address or range is dropped
// at the inbound transport layer (FWPM_LAYER_INBOUND_TRANSPORT_V4/V6), so
// answers to connections this machine opened to it are dropped too. The
// rules are described here without Windows types so they can be tested
// everywhere; ban_windows.go installs them.
//
// Safety first, a wrong filter can cut the machine off the network:
//   - the filters live in a dynamic WFP session: they are gone when the
//     service ends, also after a crash;
//   - fixed permits (loopback, DHCP, IPv6 neighbour/router discovery) and
//     the never-list (gateway, DNS servers, tunnel endpoints) weigh more
//     than any block in the own sublayer, so a range ban that covers the
//     gateway leaves the gateway open;
//   - no ban is installed while the never-list is not in place;
//   - ranges wider than /16 (IPv4) or /32 (IPv6), the unspecified address,
//     multicast and loopback are refused;
//   - the number of filters is capped (BanMaxBans, BanMaxNever).

// Weights inside the own sublayer (0..15, the higher wins).
const (
	BanWeightFixed = 15 // loopback, DHCP, ND
	BanWeightNever = 14 // gateway, DNS, tunnel endpoints
	BanWeightBlock = 8  // the bans
)

// Caps. The defense's ban table holds at most BanMaxBans entries as well
// (windefense sets it), so the filter cap is only reached on a fault.
const (
	BanMaxBans  = 2048
	BanMaxNever = 128
	banFixed    = 16 // index room of the fixed permits
	// BanMaxIndex bounds the filter keys (banBase + index): fixed permits,
	// never-list, bans.
	BanMaxIndex = banFixed + BanMaxNever + BanMaxBans
)

// Narrowest allowed range widths (prefix bits): a ban never takes a
// whole provider.
const (
	BanMinBitsV4 = 16
	BanMinBitsV6 = 32
)

// BanRule is one filter at the inbound transport layer. Permit filters with
// Proto match by protocol and local port (ICMPv6: type) only; the others by
// remote address.
type BanRule struct {
	V6        bool
	Permit    bool
	Prefix    netip.Prefix // remote address range (invalid = any)
	Proto     uint8        // 17 UDP, 58 ICMPv6, 0 = any
	LocalPort uint16       // UDP local port or ICMPv6 type
	Weight    uint8
	Index     uint32
	Name      string
}

// BanFixedRules are the permits that are always there: loopback (also by
// address, the transport layer sees it), the DHCP client ports and IPv6
// neighbour/router discovery. A ban must never break the lease or the
// neighbour cache.
func BanFixedRules() []BanRule {
	r := []BanRule{
		{Permit: true, Prefix: netip.MustParsePrefix("127.0.0.0/8"), Name: "Ban: permit loopback (IPv4)"},
		{V6: true, Permit: true, Prefix: netip.MustParsePrefix("::1/128"), Name: "Ban: permit loopback (IPv6)"},
		{Permit: true, Proto: 17, LocalPort: 68, Name: "Ban: permit DHCP (IPv4)"},
		{V6: true, Permit: true, Proto: 17, LocalPort: 546, Name: "Ban: permit DHCPv6"},
	}
	for t := uint16(133); t <= 137; t++ {
		r = append(r, BanRule{V6: true, Permit: true, Proto: 58, LocalPort: t, Name: "Ban: permit ICMPv6 ND"})
	}
	for i := range r {
		r[i].Weight = BanWeightFixed
		r[i].Index = uint32(i)
	}
	return r
}

// NormNever cleans the never-list: valid, masked, sorted, without
// duplicates, IPv4-mapped addresses as IPv4. More than BanMaxNever entries
// is an error (better no bans than a gateway that could be blocked).
func NormNever(p []netip.Prefix) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, x := range p {
		if !x.IsValid() {
			continue
		}
		a := x.Addr().Unmap().WithZone("")
		bits := x.Bits()
		if x.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				bits = 0
			}
		}
		n := netip.PrefixFrom(a, bits).Masked()
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) > BanMaxNever {
		return nil, fmt.Errorf("never-list too long (%d, at most %d)", len(out), BanMaxNever)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out, nil
}

// BanNeverRules turns a clean never-list (NormNever) into permits.
func BanNeverRules(never []netip.Prefix) []BanRule {
	out := make([]BanRule, 0, len(never))
	for i, p := range never {
		fam := "IPv4"
		if p.Addr().Is6() {
			fam = "IPv6"
		}
		out = append(out, BanRule{V6: p.Addr().Is6(), Permit: true, Prefix: p, Weight: BanWeightNever,
			Index: banFixed + uint32(i), Name: "Ban: never block (" + fam + ")"})
	}
	return out
}

// Errors of CheckBan and BanTable.
var (
	ErrBanFull    = errors.New("too many blocked addresses")
	ErrBanTooWide = errors.New("range too wide to block")
	ErrBanAddress = errors.New("address cannot be blocked (unspecified, multicast or loopback)")
	ErrBanNever   = errors.New("address is on the never-block list")
)

// BanPrefix parses the Src of a defense ban: a single address or a range.
func BanPrefix(src string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(src); err == nil {
		a = a.Unmap().WithZone("")
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(src)
	if err != nil {
		return netip.Prefix{}, err
	}
	return CheckBan(p)
}

// CheckBan validates and masks a ban.
func CheckBan(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, ErrBanAddress
	}
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() {
		a, bits = a.Unmap(), bits-96
		if bits < 0 {
			return netip.Prefix{}, ErrBanTooWide
		}
	}
	a = a.WithZone("")
	p = netip.PrefixFrom(a, bits).Masked()
	if (a.Is4() && bits < BanMinBitsV4) || (a.Is6() && bits < BanMinBitsV6) {
		return netip.Prefix{}, ErrBanTooWide
	}
	b := p.Addr()
	if b.IsUnspecified() || b.IsMulticast() || b.IsLoopback() || (b.Is4() && b.As4()[0] == 0) ||
		b == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Prefix{}, ErrBanAddress
	}
	return p, nil
}

// NeverHit reports whether a ban p is itself on the never-list (a single
// address there, or p inside a never range). A range that only contains a
// never entry is allowed: the higher-weight permit keeps that entry open.
func NeverHit(never []netip.Prefix, p netip.Prefix) bool {
	for _, n := range never {
		if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// BanFilter is one installed ban filter.
func BanFilter(p netip.Prefix, slot uint32) BanRule {
	fam := "IPv4"
	if p.Addr().Is6() {
		fam = "IPv6"
	}
	return BanRule{V6: p.Addr().Is6(), Prefix: p, Weight: BanWeightBlock, Index: banFixed + BanMaxNever + slot,
		Name: "Ban: block source (" + fam + ")"}
}

// BanTable assigns filter slots to bans (slot = index - banFixed -
// BanMaxNever). Not safe for concurrent use.
type BanTable struct {
	slots map[netip.Prefix]uint32
	free  []uint32
	next  uint32
}

// Slot returns the slot of p, or a new one; isNew is false when p is
// already there. ErrBanFull when BanMaxBans are in use.
func (t *BanTable) Slot(p netip.Prefix) (slot uint32, isNew bool, err error) {
	if t.slots == nil {
		t.slots = map[netip.Prefix]uint32{}
	}
	if s, ok := t.slots[p]; ok {
		return s, false, nil
	}
	if len(t.slots) >= BanMaxBans {
		return 0, false, ErrBanFull
	}
	if n := len(t.free); n > 0 {
		slot = t.free[n-1]
		t.free = t.free[:n-1]
	} else {
		slot = t.next
		t.next++
	}
	t.slots[p] = slot
	return slot, true, nil
}

// Release frees the slot of p (ok false: p was not there).
func (t *BanTable) Release(p netip.Prefix) (slot uint32, ok bool) {
	slot, ok = t.slots[p]
	if ok {
		delete(t.slots, p)
		t.free = append(t.free, slot)
	}
	return slot, ok
}

// Len is the number of bans.
func (t *BanTable) Len() int { return len(t.slots) }

// All returns the bans sorted.
func (t *BanTable) All() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(t.slots))
	for p := range t.slots {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Reset forgets every ban.
func (t *BanTable) Reset() { *t = BanTable{} }
