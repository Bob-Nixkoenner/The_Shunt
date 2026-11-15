//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Bans of the defense (see ban_rules.go). The Banner holds a dynamic WFP
// session for the life of the service: every object added through it is
// removed by the filter engine when the session ends, after a clean stop
// as after a crash. Provider, sublayer and filter keys are fixed, so a
// start first removes whatever an earlier run may have left.

var (
	// FWPM_LAYER_INBOUND_TRANSPORT_V4 (5926dfc8-e3cf-4426-a283-dc393f5d0f9d) defined in fwpmu.h
	cFWPM_LAYER_INBOUND_TRANSPORT_V4 = windows.GUID{Data1: 0x5926dfc8, Data2: 0xe3cf, Data3: 0x4426, Data4: [8]byte{0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d}}
	// FWPM_LAYER_INBOUND_TRANSPORT_V6 (634a869f-fc23-4b90-b0c1-bf620a36ae6f) defined in fwpmu.h
	cFWPM_LAYER_INBOUND_TRANSPORT_V6 = windows.GUID{Data1: 0x634a869f, Data2: 0xfc23, Data3: 0x4b90, Data4: [8]byte{0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f}}

	banProvider = windows.GUID{Data1: 0x5e4a7c50, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x41}}
	banSublayer = windows.GUID{Data1: 0x5e4a7c51, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x42}}
	banBase     = windows.GUID{Data1: 0x5e4a9000, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x43}}
)

// Banner installs and lifts bans. Safe for concurrent use.
type Banner struct {
	mu      sync.Mutex
	session uintptr // dynamic; 0 after Close
	tab     BanTable
	never   []netip.Prefix
	neverOK bool // the never permits are in place; no ban without them
}

func openDynamicSession() (uintptr, error) {
	dd, err := createWtFwpmDisplayData0("The Shunt defense", "The Shunt defense bans (dynamic)")
	if err != nil {
		return 0, wrapErr(err)
	}
	s := wtFwpmSession0{displayData: *dd, flags: cFWPM_SESSION_FLAG_DYNAMIC, txnWaitTimeoutInMSec: windows.INFINITE}
	h := uintptr(0)
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &s, unsafe.Pointer(&h)); err != nil {
		return 0, wrapErr(err)
	}
	return h, nil
}

func removeBans(session uintptr) {
	for i := uint32(0); i < BanMaxIndex; i++ {
		k := banBase
		k.Data1 += i
		_ = fwpmFilterDeleteByKey0(session, &k)
	}
	_ = fwpmSubLayerDeleteByKey0(session, &banSublayer)
	_ = fwpmProviderDeleteByKey0(session, &banProvider)
}

// CleanBans removes the ban objects of an earlier run (a static session; a
// dynamic one of a crashed run is already gone).
func CleanBans() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error { removeBans(session); return nil })
}

// OpenBanner cleans up, opens the dynamic session and installs provider,
// sublayer and the fixed permits. No ban is possible before SetNever.
func OpenBanner() (*Banner, error) {
	if err := CleanBans(); err != nil {
		return nil, fmt.Errorf("ban filters: cleanup: %w", err)
	}
	session, err := openDynamicSession()
	if err != nil {
		return nil, err
	}
	err = runTransaction(session, func(session uintptr) error {
		dd, err := createWtFwpmDisplayData0("The Shunt defense", "Blocked sources of the defense module")
		if err != nil {
			return wrapErr(err)
		}
		if err := wrapErr0(fwpmProviderAdd0(session, &wtFwpmProvider0{providerKey: banProvider, displayData: *dd}, 0)); err != nil {
			return err
		}
		prov := banProvider
		if err := wrapErr0(fwpmSubLayerAdd0(session, &wtFwpmSublayer0{subLayerKey: banSublayer, displayData: *dd,
			providerKey: &prov, weight: ^uint16(0) - 4}, 0)); err != nil {
			return err
		}
		for _, r := range BanFixedRules() {
			if err := addBanRule(session, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fwpmEngineClose0(session)
		return nil, err
	}
	return &Banner{session: session}, nil
}

func banLayer(v6 bool) windows.GUID {
	if v6 {
		return cFWPM_LAYER_INBOUND_TRANSPORT_V6
	}
	return cFWPM_LAYER_INBOUND_TRANSPORT_V4
}

func banKey(index uint32) windows.GUID {
	k := banBase
	k.Data1 += index
	return k
}

// condRemotePrefix matches the remote address against p (full address,
// unlike condRemoteV6 which only knows the first two bytes).
func condRemotePrefix(p netip.Prefix, keep *[]any) wtFwpmFilterCondition0 {
	if p.Addr().Is6() {
		a := &wtFwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
		*keep = append(*keep, a)
		return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(a))}}
	}
	b := p.Addr().As4()
	mask := uint32(0)
	if p.Bits() > 0 {
		mask = ^uint32(0) << uint(32-p.Bits())
	}
	return condRemoteV4(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]), mask, keep)
}

func addBanRule(session uintptr, r BanRule) error {
	if r.Index >= BanMaxIndex {
		return errors.New("ban filter index out of range")
	}
	if !r.Permit && (!r.Prefix.IsValid() || r.Proto != 0) {
		return errors.New("a ban filter needs an address and nothing else") // never a block-all
	}
	dd, err := createWtFwpmDisplayData0(r.Name, "")
	if err != nil {
		return wrapErr(err)
	}
	var keep []any
	defer runtime.KeepAlive(&keep)
	var conds []wtFwpmFilterCondition0
	if r.Proto != 0 {
		conds = append(conds, condProto(wtIPProto(r.Proto)), condLocalPort(r.LocalPort, r.LocalPort, &keep))
	}
	if r.Prefix.IsValid() {
		conds = append(conds, condRemotePrefix(r.Prefix, &keep))
	}
	if len(conds) == 0 {
		return errors.New("ban filter without conditions")
	}
	keep = append(keep, conds)
	action := cFWP_ACTION_BLOCK
	if r.Permit {
		action = cFWP_ACTION_PERMIT
	}
	prov := banProvider
	keep = append(keep, &prov)
	f := wtFwpmFilter0{
		filterKey:           banKey(r.Index),
		displayData:         *dd,
		providerKey:         &prov,
		layerKey:            banLayer(r.V6),
		subLayerKey:         banSublayer,
		weight:              filterWeight(r.Weight),
		action:              wtFwpmAction0{_type: action},
		numFilterConditions: uint32(len(conds)),
		filterCondition:     &conds[0],
	}
	var id uint64
	return wrapErr0(fwpmFilterAdd0(session, &f, 0, &id))
}

var errBannerClosed = errors.New("ban filters are closed")

// SetNever replaces the never-list permits. On an error the old ones stay
// (one transaction); a list that cannot be installed blocks all new bans.
func (b *Banner) SetNever(p []netip.Prefix) error {
	never, err := NormNever(p)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == 0 {
		return errBannerClosed
	}
	if err != nil {
		b.neverOK = false
		return err
	}
	err = runTransaction(b.session, func(session uintptr) error {
		for i := uint32(0); i < BanMaxNever; i++ {
			k := banKey(banFixed + i)
			_ = fwpmFilterDeleteByKey0(session, &k)
		}
		for _, r := range BanNeverRules(never) {
			if err := addBanRule(session, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// the old permits are still there, but they no longer match the
		// network: no new bans until a list goes in
		b.neverOK = false
		return err
	}
	b.never, b.neverOK = never, true
	return nil
}

// Add blocks p. Nothing is installed (and an error returned) when the
// never-list is not in place, p is on it, p is not a valid ban or the
// table is full.
func (b *Banner) Add(p netip.Prefix) error {
	p, err := CheckBan(p)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == 0 {
		return errBannerClosed
	}
	if !b.neverOK {
		return errors.New("never-list not in place, no bans")
	}
	if NeverHit(b.never, p) {
		return ErrBanNever
	}
	slot, isNew, err := b.tab.Slot(p)
	if err != nil || !isNew {
		return err
	}
	if err := runTransaction(b.session, func(session uintptr) error { return addBanRule(session, BanFilter(p, slot)) }); err != nil {
		b.tab.Release(p)
		return err
	}
	return nil
}

// Remove lifts the ban of p (no error when there is none).
func (b *Banner) Remove(p netip.Prefix) error {
	p, err := CheckBan(p)
	if err != nil {
		return nil // never installed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == 0 {
		return nil
	}
	slot, ok := b.tab.Release(p)
	if !ok {
		return nil
	}
	k := banKey(BanFilter(p, slot).Index)
	if err := fwpmFilterDeleteByKey0(b.session, &k); err != nil {
		return wrapErr(err)
	}
	return nil
}

// Clear lifts every ban (the never-list and the fixed permits stay).
func (b *Banner) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == 0 {
		return nil
	}
	return b.clearLocked()
}

func (b *Banner) clearLocked() error {
	var first error
	for _, p := range b.tab.All() {
		slot, _ := b.tab.Release(p)
		k := banKey(BanFilter(p, slot).Index)
		if err := fwpmFilterDeleteByKey0(b.session, &k); err != nil && first == nil {
			first = wrapErr(err)
		}
	}
	b.tab.Reset()
	return first
}

// Len is the number of installed bans.
func (b *Banner) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tab.Len()
}

// Close lifts every ban and ends the session: the engine removes all its
// objects. Safe to call twice.
func (b *Banner) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == 0 {
		return nil
	}
	_ = b.clearLocked()
	err := fwpmEngineClose0(b.session) // dynamic: never-list, permits, sublayer, provider go with it
	b.session = 0
	b.neverOK = false
	return err
}
