//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

// Package wfp is the Windows kill switch on the Windows Filtering Platform:
// a sublayer with the highest weight that blocks everything except the
// Shunt service, the Shunt adapter, loopback, DHCP/NDP and the local network
// (without its DNS). Unlike Windows Firewall rules, Windows' own allow rules
// cannot punch through it.
//
// Derived from wireguard-windows tunnel/firewall (MIT, see LICENSE.wireguard).
// Changed for The Shunt: the filters are persistent (they stay while the
// service is stopped, after a crash and across reboots), have fixed keys so
// a later run or "killswitch-off" can remove them, and the local network is
// permitted.
package wfp

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// Fixed keys: the objects outlive the process. Filter keys are filterBase
// with Data1 = filterBase.Data1 + index.
var (
	providerKey = windows.GUID{Data1: 0x5e4a7c10, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x01}}
	sublayerKey = windows.GUID{Data1: 0x5e4a7c11, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x02}}
	filterBase  = windows.GUID{Data1: 0x5e4a7d00, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x03}}
)

// maxFilters bounds the keys Disable tries (Enable installs about 40).
const maxFilters = 128

var nextFilter uint32

func filterKey(i uint32) windows.GUID {
	k := filterBase
	k.Data1 += i
	return k
}

// addFilter adds a persistent filter under the next fixed key.
func addFilter(session uintptr, filter *wtFwpmFilter0, id *uint64) error {
	if nextFilter >= maxFilters {
		return errors.New("too many kill switch filters")
	}
	filter.filterKey = filterKey(nextFilter)
	nextFilter++
	filter.flags |= cFWPM_FILTER_FLAG_PERSISTENT
	return fwpmFilterAdd0(session, filter, 0, id)
}

func openSession() (uintptr, error) {
	displayData, err := createWtFwpmDisplayData0("The Shunt", "The Shunt kill switch")
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *displayData,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	h := uintptr(0)
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&h)); err != nil {
		return 0, wrapErr(err)
	}
	return h, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{provider: providerKey, filters: sublayerKey}
	displayData, err := createWtFwpmDisplayData0("The Shunt", "The Shunt kill switch")
	if err != nil {
		return nil, wrapErr(err)
	}
	provider := wtFwpmProvider0{
		providerKey: bo.provider,
		displayData: *displayData,
		flags:       cFWPM_PROVIDER_FLAG_PERSISTENT,
	}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}
	displayData, err = createWtFwpmDisplayData0("The Shunt filters", "Kill switch: permits and the final block")
	if err != nil {
		return nil, wrapErr(err)
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *displayData,
		flags:       cFWPM_SUBLAYER_FLAG_PERSISTENT,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

// remove deletes our filters, sublayer and provider; missing ones are fine.
func remove(session uintptr) {
	for i := uint32(0); i < maxFilters; i++ {
		k := filterKey(i)
		_ = fwpmFilterDeleteByKey0(session, &k)
	}
	_ = fwpmSubLayerDeleteByKey0(session, &sublayerKey)
	_ = fwpmProviderDeleteByKey0(session, &providerKey)
}

// Enable installs the kill switch, replacing an earlier one: the process
// running it (the service) may send anywhere, apps only through the
// interface tunLUID (the Shunt adapter), and DNS (port 53) is blocked
// except towards dns; apps (full paths) may send anywhere, too. The filters persist until Disable.
func Enable(tunLUID uint64, dns netip.Addr, apps ...string) error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	nextFilter = 0
	return runTransaction(session, func(session uintptr) error {
		remove(session)
		bo, err := registerBaseObjects(session)
		if err != nil {
			return err
		}
		steps := []func() error{
			func() error { return permitWireGuardService(session, bo, 15, "") },
			func() error { return blockDNS([]netip.Addr{dns}, session, bo, 15, 14) },
			func() error { return permitLoopback(session, bo, 13) },
			func() error { return permitTunInterface(session, bo, 12, tunLUID) },
			func() error { return permitDHCPIPv4(session, bo, 12) },
			func() error { return permitDHCPIPv6(session, bo, 12) },
			func() error { return permitNdp(session, bo, 12) },
			func() error { return permitLAN(session, bo, 11) },
			func() error { return blockAll(session, bo, 0) },
		}
		// programs that carry a tunnel themselves (tor.exe and its transports
		// for a Tor tunnel): like the service they may send anywhere
		for _, a := range apps {
			a := a
			steps = append([]func() error{func() error { return permitWireGuardService(session, bo, 15, a) }}, steps...)
		}
		for _, s := range steps {
			if err := s(); err != nil {
				return err
			}
		}
		return nil
	})
}

// Disable removes the kill switch (also one left by an earlier run).
func Disable() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, func(session uintptr) error { remove(session); return nil })
}
