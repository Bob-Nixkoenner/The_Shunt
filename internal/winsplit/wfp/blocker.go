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

// Boot-time copies (FWPM_FILTER_FLAG_BOOTTIME): the TCP/IP stack enforces
// them from its start until BFE runs and loads the persistent filters above.
// Without them the first seconds of a boot are open (Windows' NCSI check went
// out in plain text before BFE had loaded the kill switch). They take no
// provider and sit in the default sublayer, so they do not depend on objects
// BFE only loads later.
var bootFilterBase = windows.GUID{Data1: 0x5e4a8000, Data2: 0x5f3b, Data3: 0x4c2e, Data4: [8]byte{0x9a, 0x61, 0x53, 0x48, 0x55, 0x4e, 0x54, 0x04}}

// maxFilters bounds the keys Disable tries (Enable installs about 40).
const maxFilters = 128

// maxBootFilters bounds the boot-time keys (the same set as the persistent one).
const maxBootFilters = maxFilters

var nextFilter, nextBootFilter uint32

// bootGen is the key set (0 or 1) the boot-time copies are added under.
var bootGen uint8

// bootMode: addFilter adds boot-time filters instead of persistent ones.
var bootMode bool

func filterKey(i uint32) windows.GUID {
	k := filterBase
	k.Data1 += i
	return k
}

func bootFilterKey(i uint32) windows.GUID { return genKey(bootFilterBase, bootGen, i) }

// Boot-time copies alternate between two key sets. BFE leaves a boot-time
// filter out of the boot-time policy when its key is deleted and added again
// in one transaction: the filter is live, but missing from "netsh wfp show
// boottimepolicy", so after a hard power-off the next boot had none of them
// (the NCSI probe went out in plain text, lab WD05/D07; seen in the VM, a
// fresh key or a delete-and-add of another key is stored at once). So every
// refresh adds the set not in use and deletes the other one.

// genKey is key i of generation gen (0 or 1) of base; generation 1 differs
// in the last byte, so Data1 (what the lab counts by) stays the same.
func genKey(base windows.GUID, gen uint8, i uint32) windows.GUID {
	k := base
	k.Data1 += i
	if gen == 1 {
		k.Data4[7]++
	}
	return k
}

// swapGen deletes both generations of base (keys 0..n-1) and returns the
// one to add next: the one that held no filters (0 when neither or, after an
// odd state, both did; the next refresh is right again).
func swapGen(session uintptr, base windows.GUID, n uint32) uint8 {
	return nextGen(func(k *windows.GUID) bool { return fwpmFilterDeleteByKey0(session, k) == nil }, base, n)
}

// nextGen is swapGen with del deleting one key (true = it existed).
func nextGen(del func(*windows.GUID) bool, base windows.GUID, n uint32) uint8 {
	var had [2]bool
	for gen := uint8(0); gen < 2; gen++ {
		for i := uint32(0); i < n; i++ {
			k := genKey(base, gen, i)
			if del(&k) {
				had[gen] = true
			}
		}
	}
	if had[0] && !had[1] {
		return 1
	}
	return 0
}

// addFilter adds a persistent filter under the next fixed key (in bootMode a
// boot-time filter without provider, in the default sublayer).
func addFilter(session uintptr, filter *wtFwpmFilter0, id *uint64) error {
	if bootMode {
		if nextBootFilter >= maxBootFilters {
			return errors.New("too many kill switch boot-time filters")
		}
		f := *filter
		f.filterKey = bootFilterKey(nextBootFilter)
		nextBootFilter++
		f.flags = f.flags&^cFWPM_FILTER_FLAG_PERSISTENT | cFWPM_FILTER_FLAG_BOOTTIME
		f.providerKey = nil
		f.subLayerKey = windows.GUID{} // FWPM_SUBLAYER_UNIVERSAL
		return fwpmFilterAdd0(session, &f, 0, id)
	}
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

// remove deletes our filters (both boot-time key sets), sublayer and
// provider; missing ones are fine.
func remove(session uintptr) {
	swapGen(session, bootFilterBase, maxBootFilters)
	removePersistent(session)
}

func removePersistent(session uintptr) {
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
	nextFilter, nextBootFilter, bootMode = 0, 0, false
	defer func() { bootMode = false }()
	return runTransaction(session, func(session uintptr) error {
		bootGen = swapGen(session, bootFilterBase, maxBootFilters)
		removePersistent(session)
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
		// the same set again as boot-time filters, for the seconds before BFE
		// loads the persistent ones (should Windows also enforce them while
		// BFE runs, they only repeat the persistent set one sublayer lower)
		bootMode = true
		for _, s := range steps {
			if err := s(); err != nil {
				return err
			}
		}
		bootMode = false
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
