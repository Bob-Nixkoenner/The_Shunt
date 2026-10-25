// The Shunt additions to the wireguard-windows filters: the local network
// permit and the delete calls a persistent kill switch needs.

package wfp

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cFWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001 // fwpmtypes.h

var (
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
)

// The fwpm calls return their error code (not GetLastError).
func fwpmCall(p *windows.LazyProc, args ...uintptr) error {
	r1, _, _ := p.Call(args...)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmFilterDeleteByKey0(engine uintptr, key *windows.GUID) error {
	return fwpmCall(procFwpmFilterDeleteByKey0, engine, uintptr(unsafe.Pointer(key)))
}

func fwpmSubLayerDeleteByKey0(engine uintptr, key *windows.GUID) error {
	return fwpmCall(procFwpmSubLayerDeleteByKey0, engine, uintptr(unsafe.Pointer(key)))
}

func fwpmProviderDeleteByKey0(engine uintptr, key *windows.GUID) error {
	return fwpmCall(procFwpmProviderDeleteByKey0, engine, uintptr(unsafe.Pointer(key)))
}

// Local networks: private, link-local and multicast ranges (never public
// ones, so a network that claims 1.1.1.0/24 gains nothing: TunnelCrack
// LocalNet). DNS towards them is blocked by the higher-weight DNS filter.
var (
	lanV4 = []wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000}, // 10.0.0.0/8
		{0xac100000, 0xfff00000}, // 172.16.0.0/12
		{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
		{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
		{0xe0000000, 0xf0000000}, // 224.0.0.0/4
		{0xffffffff, 0xffffffff}, // 255.255.255.255
	}
	lanV6 = []wtFwpV6AddrAndMask{
		{[16]uint8{0xfe, 0x80}, 10}, // fe80::/10
		{[16]uint8{0xfc}, 7},        // fc00::/7
		{[16]uint8{0xff}, 8},        // ff00::/8
	}
)

// permitLAN lets everything reach the local network, both directions (the
// same reach as before the WFP kill switch: printers, NAS, the router).
func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	v4 := make([]wtFwpmFilterCondition0, len(lanV4))
	for i := range lanV4 {
		v4[i].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS // repeated field = OR
		v4[i].matchType = cFWP_MATCH_EQUAL
		v4[i].conditionValue._type = cFWP_V4_ADDR_MASK
		v4[i].conditionValue.value = uintptr(unsafe.Pointer(&lanV4[i]))
	}
	v6 := make([]wtFwpmFilterCondition0, len(lanV6))
	for i := range lanV6 {
		v6[i].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		v6[i].matchType = cFWP_MATCH_EQUAL
		v6[i].conditionValue._type = cFWP_V6_ADDR_MASK
		v6[i].conditionValue.value = uintptr(unsafe.Pointer(&lanV6[i]))
	}
	for _, l := range []struct {
		name  string
		layer windows.GUID
		conds []wtFwpmFilterCondition0
	}{
		{"Permit outbound traffic to the local network (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, v4},
		{"Permit inbound traffic from the local network (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, v4},
		{"Permit outbound traffic to the local network (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, v6},
		{"Permit inbound traffic from the local network (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, v6},
	} {
		displayData, err := createWtFwpmDisplayData0(l.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            l.layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(l.conds)),
			filterCondition:     &l.conds[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		id := uint64(0)
		if err := addFilter(session, &filter, &id); err != nil {
			return wrapErr(err)
		}
	}
	runtime.KeepAlive(lanV4)
	runtime.KeepAlive(lanV6)
	return nil
}
