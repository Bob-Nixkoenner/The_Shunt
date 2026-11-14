//go:build windows

package wfp

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exit guard filters (see ExitFilters): a provider and sublayer of their
// own, not persistent. They stay while BFE runs, so after a crash of the
// service the exit addresses stay closed to other listeners (fail closed),
// and they are gone after a reboot; the next run sets them again. The
// sublayer is weighed on its own, so a block here also holds against the
// kill switch's loopback permit (a soft permit); the kill switch's permit
// for the service (a hard permit) only concerns the service itself.

var (
	exProvider = windows.GUID{Data1: 0x5e4a7c40, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x31}}
	exSublayer = windows.GUID{Data1: 0x5e4a7c41, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x32}}
	exBase     = windows.GUID{Data1: 0x5e4a8200, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x33}}
)

func exitLayerKey(l ExitLayer, v6 bool) windows.GUID {
	switch {
	case l == ExitLayerAccept && v6:
		return cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	case l == ExitLayerAccept:
		return cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
	case v6:
		return cFWPM_LAYER_ALE_AUTH_CONNECT_V6
	}
	return cFWPM_LAYER_ALE_AUTH_CONNECT_V4
}

// ownerSD is the security descriptor of the permits' ALE_USER_ID
// condition: the process runs as the same account as this one. For the
// service that is SYSTEM, as in the M-07 permit (tor.exe runs as its child);
// the filters are not persistent, so unlike the kill switch they can name
// the current account ("shuntd-win run" from an admin console works too).
func ownerSD() (*windows.SECURITY_DESCRIPTOR, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("O:SYD:(A;;CCRC;;;" + tu.User.Sid.String() + ")")
}

// exitConds builds the conditions of f; pointers handed to the engine are
// appended to keep, app IDs to free.
func exitConds(f ExitFilter, keep *[]any, free *[]*wtFwpByteBlob) ([]wtFwpmFilterCondition0, error) {
	portField, addrField := cFWPM_CONDITION_IP_LOCAL_PORT, cFWPM_CONDITION_IP_LOCAL_ADDRESS
	if f.Layer == ExitLayerConnect {
		portField, addrField = cFWPM_CONDITION_IP_REMOTE_PORT, cFWPM_CONDITION_IP_REMOTE_ADDRESS
	}
	conds := []wtFwpmFilterCondition0{
		condProto(cIPPROTO_TCP),
		{fieldKey: portField, matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(f.Addr.Port())}},
	}
	if ip := f.Addr.Addr(); !ip.IsUnspecified() {
		if f.V6 {
			a := &wtFwpV6AddrAndMask{addr: ip.As16(), prefixLength: 128}
			*keep = append(*keep, a)
			conds = append(conds, wtFwpmFilterCondition0{fieldKey: addrField, matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(a))}})
		} else {
			b := ip.As4()
			a := &wtFwpV4AddrAndMask{addr: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), mask: ^uint32(0)}
			*keep = append(*keep, a)
			conds = append(conds, wtFwpmFilterCondition0{fieldKey: addrField, matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(a))}})
		}
	}
	if !f.Permit {
		return conds, nil
	}
	appID, err := getAppID(f.App)
	if err != nil {
		return nil, err
	}
	*free = append(*free, appID)
	conds = append(conds, wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_ALE_APP_ID, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_BYTE_BLOB_TYPE, value: uintptr(unsafe.Pointer(appID))}})
	sd, err := ownerSD()
	if err != nil {
		return nil, wrapErr(err)
	}
	blob := &wtFwpByteBlob{size: sd.Length(), data: (*uint8)(unsafe.Pointer(sd))}
	*keep = append(*keep, sd, blob)
	conds = append(conds, wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_ALE_USER_ID, matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_SECURITY_DESCRIPTOR_TYPE, value: uintptr(unsafe.Pointer(blob))}})
	return conds, nil
}

// SetExitGuard installs the exit guard for gs, replacing the earlier set;
// an empty gs removes it.
func SetExitGuard(gs []ExitGuard) error {
	fs, err := ExitFilters(gs)
	if err != nil {
		return err
	}
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error {
		removeExitGuard(session)
		if len(fs) == 0 {
			return nil
		}
		dd, err := createWtFwpmDisplayData0("The Shunt exit guard", "SOCKS exit and Tor addresses belong to the Shunt service")
		if err != nil {
			return wrapErr(err)
		}
		if err := wrapErr0(fwpmProviderAdd0(session, &wtFwpmProvider0{providerKey: exProvider, displayData: *dd}, 0)); err != nil {
			return err
		}
		prov := exProvider
		if err := wrapErr0(fwpmSubLayerAdd0(session, &wtFwpmSublayer0{subLayerKey: exSublayer, displayData: *dd,
			providerKey: &prov, weight: ^uint16(0) - 3}, 0)); err != nil {
			return err
		}
		var keep []any
		var free []*wtFwpByteBlob
		defer func() {
			for i := range free {
				fwpmFreeMemory0(unsafe.Pointer(&free[i]))
			}
			runtime.KeepAlive(&keep)
		}()
		for _, ef := range fs {
			fd, err := createWtFwpmDisplayData0(ef.Name, "")
			if err != nil {
				return wrapErr(err)
			}
			conds, err := exitConds(ef, &keep, &free)
			if err != nil {
				return err
			}
			keep = append(keep, conds)
			action := cFWP_ACTION_BLOCK
			if ef.Permit {
				action = cFWP_ACTION_PERMIT
			}
			k := exBase
			k.Data1 += ef.Index
			f := wtFwpmFilter0{
				filterKey:           k,
				displayData:         *fd,
				providerKey:         &prov,
				layerKey:            exitLayerKey(ef.Layer, ef.V6),
				subLayerKey:         exSublayer,
				weight:              filterWeight(ef.Weight),
				action:              wtFwpmAction0{_type: action},
				numFilterConditions: uint32(len(conds)),
				filterCondition:     &conds[0],
			}
			var id uint64
			if err := wrapErr0(fwpmFilterAdd0(session, &f, 0, &id)); err != nil {
				return err
			}
		}
		return nil
	})
}

func removeExitGuard(session uintptr) {
	for i := uint32(0); i < ExitMaxIndex; i++ {
		k := exBase
		k.Data1 += i
		_ = fwpmFilterDeleteByKey0(session, &k)
	}
	_ = fwpmSubLayerDeleteByKey0(session, &exSublayer)
	_ = fwpmProviderDeleteByKey0(session, &exProvider)
}
