//go:build windows

package wfp

import (
	"errors"
	"runtime"

	"golang.org/x/sys/windows"
)

// Quiet mode: outgoing discovery (see QuietRules, QuietFilters) is dropped at
// the ALE connect layers and at the outbound transport layers, in a sublayer
// of its own. The filters are persistent, like the kill switch's: they also
// hold in the minutes between boot and the start of the service, and while
// it is stopped. The service takes them away on a trusted network
// (EnableQuiet/DisableQuiet follow the network profile). Several sublayers
// are all weighed and a block anywhere wins, so the kill switch's permit for
// the local network cannot open them again. Each filter also has a boot-time
// copy for the seconds before BFE runs (LLMNR went out in the first seconds
// of a boot before the persistent filters were loaded). The set does not
// depend on the network, so the boot set is the same as the running one.

var (
	quProvider = windows.GUID{Data1: 0x5e4a7c30, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x21}}
	quSublayer = windows.GUID{Data1: 0x5e4a7c31, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x22}}
	quBase     = windows.GUID{Data1: 0x5e4a7f00, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x23}}
	// boot-time copies (see bootFilterBase): enforced from the start of the
	// TCP/IP stack until BFE loads the persistent filters
	quBootBase = windows.GUID{Data1: 0x5e4a8100, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x24}}
)

// quMaxFilters bounds the keys removeQuiet tries (QuietMaxIndex).
const quMaxFilters = QuietMaxIndex

func quietLayerKey(l QuietLayer, v6 bool) windows.GUID {
	switch {
	case l == QuietLayerTransport && v6:
		return cFWPM_LAYER_OUTBOUND_TRANSPORT_V6
	case l == QuietLayerTransport:
		return cFWPM_LAYER_OUTBOUND_TRANSPORT_V4
	case v6:
		return cFWPM_LAYER_ALE_AUTH_CONNECT_V6
	}
	return cFWPM_LAYER_ALE_AUTH_CONNECT_V4
}

// quietConds builds the conditions of r (nil: none, the filter matches all).
func quietConds(r QuietRule, keep *[]any) []wtFwpmFilterCondition0 {
	var conds []wtFwpmFilterCondition0
	if r.Proto != 0 {
		conds = append(conds, condProto(wtIPProto(r.Proto)))
		if r.Proto == uint8(cIPPROTO_ICMPV6) {
			conds = append(conds, condLocalPort(r.RemotePort, r.RemotePort, keep)) // ICMP type
		} else if r.RemotePort != 0 {
			conds = append(conds, wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_PORT, matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(r.RemotePort)}})
		}
	}
	if r.Prefix.IsValid() {
		if r.V6 {
			a := r.Prefix.Addr().As16()
			conds = append(conds, condRemoteV6(a[0], a[1], uint8(r.Prefix.Bits()), keep))
		} else {
			a := r.Prefix.Addr().As4()
			addr := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
			mask := ^uint32(0) << uint(32-r.Prefix.Bits())
			conds = append(conds, condRemoteV4(addr, mask, keep))
		}
	}
	if r.DestBroadcast {
		conds = append(conds, wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE, matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(cNlatBroadcast)}})
	}
	if len(conds) == 0 {
		return nil
	}
	*keep = append(*keep, conds)
	return conds
}

// EnableQuiet installs the quiet-mode filters (replacing earlier ones).
func EnableQuiet() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error {
		removeQuiet(session)
		dd, err := createWtFwpmDisplayData0("The Shunt quiet mode", "No discovery traffic out of the network")
		if err != nil {
			return wrapErr(err)
		}
		if err := wrapErr0(fwpmProviderAdd0(session, &wtFwpmProvider0{providerKey: quProvider, displayData: *dd,
			flags: cFWPM_PROVIDER_FLAG_PERSISTENT}, 0)); err != nil {
			return err
		}
		prov := quProvider
		if err := wrapErr0(fwpmSubLayerAdd0(session, &wtFwpmSublayer0{subLayerKey: quSublayer, displayData: *dd,
			flags: cFWPM_SUBLAYER_FLAG_PERSISTENT, providerKey: &prov, weight: ^uint16(0) - 2}, 0)); err != nil {
			return err
		}
		var keep []any
		defer runtime.KeepAlive(&keep)
		for _, qf := range QuietFilters() {
			if qf.Index >= quMaxFilters {
				return errors.New("too many quiet filters")
			}
			fd, err := createWtFwpmDisplayData0(qf.Name, "")
			if err != nil {
				return wrapErr(err)
			}
			action := cFWP_ACTION_BLOCK
			if qf.Rule.Permit {
				action = cFWP_ACTION_PERMIT
			}
			// persistent in the own sublayer, and a boot-time copy without
			// provider in the default sublayer; there it shares the sublayer
			// with the kill switch's boot-time copies, so its weights put the
			// drops above the kill switch's LAN/DHCP permits (QuietWeight)
			k, flags, sub, pk := quBase, cFWPM_FILTER_FLAG_PERSISTENT, quSublayer, &prov
			if qf.Boot {
				k, flags, sub, pk = quBootBase, cFWPM_FILTER_FLAG_BOOTTIME, windows.GUID{}, nil
			}
			k.Data1 += qf.Index
			f := wtFwpmFilter0{
				filterKey:   k,
				displayData: *fd,
				flags:       flags,
				providerKey: pk,
				layerKey:    quietLayerKey(qf.Layer, qf.Rule.V6),
				subLayerKey: sub,
				weight:      filterWeight(qf.Weight),
				action:      wtFwpmAction0{_type: action},
			}
			if cs := quietConds(qf.Rule, &keep); len(cs) > 0 {
				f.numFilterConditions = uint32(len(cs))
				f.filterCondition = &cs[0]
			}
			var id uint64
			if err := wrapErr0(fwpmFilterAdd0(session, &f, 0, &id)); err != nil {
				return err
			}
		}
		return nil
	})
}

func removeQuiet(session uintptr) {
	for i := uint32(0); i < quMaxFilters; i++ {
		k := quBase
		k.Data1 += i
		_ = fwpmFilterDeleteByKey0(session, &k)
		k = quBootBase
		k.Data1 += i
		_ = fwpmFilterDeleteByKey0(session, &k)
	}
	_ = fwpmSubLayerDeleteByKey0(session, &quSublayer)
	_ = fwpmProviderDeleteByKey0(session, &quProvider)
}

// DisableQuiet removes the quiet-mode filters (safe when none exist).
func DisableQuiet() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error { removeQuiet(session); return nil })
}
