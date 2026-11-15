//go:build windows

package netdetect

import (
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Current is not filled here: the Windows service builds Info itself
// (winsplit); only the public-address flags come from this package.
func Current() Info { return WithPublic(Info{}) }

// WindowsProfile returns the network profile ("public", "private",
// "domain") Windows gives the network on adapter iface (friendly name), or
// "" when it cannot be read. It asks the Network List Manager over COM; call
// it when the network changes, not in a loop.
func WindowsProfile(iface string) string {
	conns, err := nlmConnections()
	if err != nil {
		return ""
	}
	return PickProfile(conns, iface)
}

const clsctxAll = 0x17 // CLSCTX_INPROC_SERVER|INPROC_HANDLER|LOCAL_SERVER|REMOTE_SERVER

var procCoCreateInstance = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")

var (
	clsidNLM = windows.GUID{Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B, Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
	iidNLM   = windows.GUID{Data1: 0xDCB00000, Data2: 0x570F, Data3: 0x4A9B, Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
)

// vtable slots (IDispatch takes 0..6)
const (
	slotRelease        = 2
	slotNLMConnections = 9  // INetworkListManager::GetNetworkConnections
	slotEnumNext       = 8  // IEnumNetworkConnections::Next
	slotConnNetwork    = 7  // INetworkConnection::GetNetwork
	slotConnAdapter    = 12 // INetworkConnection::GetAdapterId
	slotNetCategory    = 18 // INetwork::GetCategory
)

func vcall(obj uintptr, slot int, args ...uintptr) uintptr {
	// obj is a COM interface pointer: its first word points to the vtable
	p := *(*unsafe.Pointer)(unsafe.Pointer(&obj))
	vt := *(*unsafe.Pointer)(p)
	fn := *(*uintptr)(unsafe.Add(vt, slot*int(unsafe.Sizeof(uintptr(0)))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{obj}, args...)...)
	return r
}

func release(obj uintptr) {
	if obj != 0 {
		vcall(obj, slotRelease)
	}
}

func nlmConnections() (out []ProfileConn, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// S_FALSE / RPC_E_CHANGED_MODE: COM is usable on this thread anyway
	_ = windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	defer windows.CoUninitialize()

	var nlm uintptr
	if hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNLM)), 0, clsctxAll,
		uintptr(unsafe.Pointer(&iidNLM)), uintptr(unsafe.Pointer(&nlm))); int32(hr) < 0 || nlm == 0 {
		return nil, windows.Errno(hr)
	}
	defer release(nlm)
	var enum uintptr
	if hr := vcall(nlm, slotNLMConnections, uintptr(unsafe.Pointer(&enum))); int32(hr) < 0 {
		return nil, windows.Errno(hr)
	}
	defer release(enum)
	names := adapterNames()
	for i := 0; i < 32; i++ {
		var conn uintptr
		var got uint32
		if hr := vcall(enum, slotEnumNext, 1, uintptr(unsafe.Pointer(&conn)), uintptr(unsafe.Pointer(&got))); int32(hr) < 0 || got == 0 || conn == 0 {
			break
		}
		var guid windows.GUID
		var netw uintptr
		var cat int32 = -1
		if int32(vcall(conn, slotConnNetwork, uintptr(unsafe.Pointer(&netw)))) >= 0 && netw != 0 {
			vcall(netw, slotNetCategory, uintptr(unsafe.Pointer(&cat)))
			release(netw)
		}
		vcall(conn, slotConnAdapter, uintptr(unsafe.Pointer(&guid)))
		release(conn)
		if cat >= 0 {
			out = append(out, ProfileConn{Adapter: names[strings.ToUpper(guid.String())], Category: int(cat)})
		}
	}
	return out, nil
}

// adapterNames maps the adapter GUID ("{...}") to its friendly name.
func adapterNames() map[string]string {
	m := map[string]string{}
	size := uint32(15000)
	for try := 0; try < 3; try++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return m
		}
		for a := aa; a != nil; a = a.Next {
			m[strings.ToUpper(windows.BytePtrToString(a.AdapterName))] = windows.UTF16PtrToString(a.FriendlyName)
		}
		break
	}
	return m
}
