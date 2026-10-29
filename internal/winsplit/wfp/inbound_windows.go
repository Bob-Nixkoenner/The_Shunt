//go:build windows

package wfp

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Inbound protection: new connections from the network to this machine are
// blocked (WFP layer ALE_AUTH_RECV_ACCEPT, which sees the first packet of a
// flow only: answers to our own connections are not touched). A sublayer of
// its own, not persistent: when the service is gone, Windows Firewall alone
// protects, as before. Unlike Windows Firewall rules, allow rules that
// installers added cannot open ports behind it.

// InboundPort is one open port in mode "lan" (From == To for a single port).
type InboundPort struct {
	TCP      bool
	From, To uint16
}

// InboundPolicy: Allow nil and LAN false = closed. LAN true lets the ports
// in Allow in from private addresses only. TunLUID (if not 0) is never opened:
// nothing comes in through the tunnel.
type InboundPolicy struct {
	LAN     bool
	Allow   []InboundPort
	TunLUID uint64
}

var (
	inProvider = windows.GUID{Data1: 0x5e4a7c20, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x11}}
	inSublayer = windows.GUID{Data1: 0x5e4a7c21, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x12}}
	inBase     = windows.GUID{Data1: 0x5e4a7e00, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x13}}
)

const inMaxFilters = 512

type wtFwpRange0 struct{ low, high wtFwpValue0 }

type inState struct {
	session uintptr
	next    uint32
	keep    []any // pointers handed to the engine live until the transaction ends
}

func (s *inState) add(name string, layer windows.GUID, weight uint8, action wtFwpActionType, conds []wtFwpmFilterCondition0) error {
	if s.next >= inMaxFilters {
		return errors.New("too many inbound filters")
	}
	dd, err := createWtFwpmDisplayData0(name, "")
	if err != nil {
		return wrapErr(err)
	}
	k := inBase
	k.Data1 += s.next
	s.next++
	prov := inProvider
	f := wtFwpmFilter0{
		filterKey:   k,
		displayData: *dd,
		providerKey: &prov,
		layerKey:    layer,
		subLayerKey: inSublayer,
		weight:      filterWeight(weight),
		action:      wtFwpmAction0{_type: action},
	}
	if len(conds) > 0 {
		cs := append([]wtFwpmFilterCondition0(nil), conds...)
		s.keep = append(s.keep, cs, &prov)
		f.numFilterConditions = uint32(len(cs))
		f.filterCondition = &cs[0]
	}
	var id uint64
	return wrapErr0(fwpmFilterAdd0(s.session, &f, 0, &id))
}

func wrapErr0(err error) error {
	if err == nil {
		return nil
	}
	return wrapErr(err)
}

func condProto(p wtIPProto) wtFwpmFilterCondition0 {
	return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_PROTOCOL, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(p)}}
}

func condLocalPort(from, to uint16, keep *[]any) wtFwpmFilterCondition0 {
	if from == to {
		return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_LOCAL_PORT, matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(from)}}
	}
	r := &wtFwpRange0{low: wtFwpValue0{_type: cFWP_UINT16, value: uintptr(from)}, high: wtFwpValue0{_type: cFWP_UINT16, value: uintptr(to)}}
	*keep = append(*keep, r)
	return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_LOCAL_PORT, matchType: cFWP_MATCH_RANGE,
		conditionValue: wtFwpConditionValue0{_type: cFWP_RANGE_TYPE, value: uintptr(unsafe.Pointer(r))}}
}

func condRemoteV4(addr, mask uint32, keep *[]any) wtFwpmFilterCondition0 {
	a := &wtFwpV4AddrAndMask{addr: addr, mask: mask}
	*keep = append(*keep, a)
	return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(a))}}
}

func condRemoteV6(first byte, second byte, prefix uint8, keep *[]any) wtFwpmFilterCondition0 {
	a := &wtFwpV6AddrAndMask{prefixLength: prefix}
	a.addr[0], a.addr[1] = first, second
	*keep = append(*keep, a)
	return wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(a))}}
}

// EnableInbound installs the filters for p, replacing an earlier policy.
func EnableInbound(p InboundPolicy) error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error {
		removeInbound(session)
		dd, err := createWtFwpmDisplayData0("The Shunt inbound", "The Shunt inbound protection")
		if err != nil {
			return wrapErr(err)
		}
		if err := wrapErr0(fwpmProviderAdd0(session, &wtFwpmProvider0{providerKey: inProvider, displayData: *dd}, 0)); err != nil {
			return err
		}
		prov := inProvider
		if err := wrapErr0(fwpmSubLayerAdd0(session, &wtFwpmSublayer0{subLayerKey: inSublayer, displayData: *dd,
			providerKey: &prov, weight: ^uint16(0) - 1}, 0)); err != nil {
			return err
		}
		s := &inState{session: session}
		defer runtime.KeepAlive(s)
		layers := []struct {
			l  windows.GUID
			v6 bool
		}{{cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false}, {cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true}}
		for _, ly := range layers {
			fam := "IPv4"
			if ly.v6 {
				fam = "IPv6"
			}
			loop := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_FLAGS, matchType: cFWP_MATCH_FLAGS_ALL_SET,
				conditionValue: wtFwpConditionValue0{_type: cFWP_UINT32, value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK)}}
			if err := s.add("Permit loopback ("+fam+")", ly.l, 15, cFWP_ACTION_PERMIT, []wtFwpmFilterCondition0{loop}); err != nil {
				return err
			}
			if ly.v6 {
				// DHCPv6 reply port and neighbour/router discovery (ICMPv6 133..137)
				if err := s.add("Permit DHCPv6", ly.l, 14, cFWP_ACTION_PERMIT, []wtFwpmFilterCondition0{condProto(cIPPROTO_UDP), condLocalPort(546, 546, &s.keep)}); err != nil {
					return err
				}
				for t := uint16(133); t <= 137; t++ {
					if err := s.add("Permit ICMPv6 ND", ly.l, 14, cFWP_ACTION_PERMIT, []wtFwpmFilterCondition0{condProto(cIPPROTO_ICMPV6), condLocalPort(t, t, &s.keep)}); err != nil {
						return err
					}
				}
			} else if err := s.add("Permit DHCP", ly.l, 14, cFWP_ACTION_PERMIT, []wtFwpmFilterCondition0{condProto(cIPPROTO_UDP), condLocalPort(68, 68, &s.keep)}); err != nil {
				return err
			}
			if p.LAN {
				for _, a := range p.Allow {
					proto := cIPPROTO_UDP
					if a.TCP {
						proto = cIPPROTO_TCP
					}
					conds := []wtFwpmFilterCondition0{condProto(proto), condLocalPort(a.From, a.To, &s.keep)}
					// several conditions on one field are alternatives: private ranges only
					if ly.v6 {
						conds = append(conds, condRemoteV6(0xfe, 0x80, 10, &s.keep), condRemoteV6(0xfc, 0x00, 7, &s.keep))
					} else {
						conds = append(conds, condRemoteV4(0x0A000000, 0xFF000000, &s.keep), condRemoteV4(0xAC100000, 0xFFF00000, &s.keep),
							condRemoteV4(0xC0A80000, 0xFFFF0000, &s.keep), condRemoteV4(0xA9FE0000, 0xFFFF0000, &s.keep))
					}
					if p.TunLUID != 0 {
						luid := new(uint64)
						*luid = p.TunLUID
						s.keep = append(s.keep, luid)
						conds = append(conds, wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_LOCAL_INTERFACE, matchType: cFWP_MATCH_NOT_EQUAL,
							conditionValue: wtFwpConditionValue0{_type: cFWP_UINT64, value: uintptr(unsafe.Pointer(luid))}})
					}
					if err := s.add("Permit inbound port from the local network ("+fam+")", ly.l, 13, cFWP_ACTION_PERMIT, conds); err != nil {
						return err
					}
				}
			}
			if err := s.add("Block inbound ("+fam+")", ly.l, 0, cFWP_ACTION_BLOCK, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func removeInbound(session uintptr) {
	for i := uint32(0); i < inMaxFilters; i++ {
		k := inBase
		k.Data1 += i
		_ = fwpmFilterDeleteByKey0(session, &k)
	}
	_ = fwpmSubLayerDeleteByKey0(session, &inSublayer)
	_ = fwpmProviderDeleteByKey0(session, &inProvider)
}

// DisableInbound removes the inbound filters (safe when none exist).
func DisableInbound() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error { removeInbound(session); return nil })
}
