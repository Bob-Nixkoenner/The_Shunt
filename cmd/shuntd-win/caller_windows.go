package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Bob-Nixkoenner/the_shunt/internal/winsvc"
)

// Who is calling the API: the AF_UNIX socket tells the peer's PID
// (SIO_AF_UNIX_GETPEERPID, Windows 10 1809+), that process's token tells
// the account and its groups. The service runs as SYSTEM, so it may open
// every process for that.

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID (afunix.h):
// _WSAIOR(IOC_VENDOR, 256).
const sioAFUnixGetPeerPID = 0x40000000 | 0x18000000 | 256

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	procNetLocalGroupAdd        = netapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
)

// peerPID returns the PID of the process on the other end of c.
func peerPID(c net.Conn) (uint32, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid, n uint32
	var ierr error
	if err := raw.Control(func(fd uintptr) {
		ierr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0, (*byte)(unsafe.Pointer(&pid)), 4, &n, nil, 0)
	}); err != nil {
		return 0, err
	}
	if ierr != nil {
		return 0, ierr
	}
	if pid == 0 {
		return 0, errors.New("no peer pid")
	}
	return pid, nil
}

// identify returns the caller on c, nil if it cannot be told (then the
// caller may only read). group is the manage group.
func identify(c net.Conn, group string) *winsvc.Caller {
	accepted := time.Now()
	pid, err := peerPID(c)
	if err != nil {
		log.Printf("api: caller unknown: %v", err)
		return nil
	}
	who, err := callerOf(pid, group)
	if err != nil {
		log.Printf("api: caller pid %d: %v", pid, err)
		return nil
	}
	// the process must be older than the connection: a PID recycled
	// between connect and now is not the caller
	if who.Created.After(accepted) {
		log.Printf("api: caller pid %d is younger than its connection", pid)
		return nil
	}
	return who
}

func callerOf(pid uint32, group string) (*winsvc.Caller, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kt, ut windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kt, &ut); err != nil {
		return nil, err
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, err
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	user := tu.User.Sid
	who := &winsvc.Caller{PID: int(pid), Created: time.Unix(0, created.Nanoseconds()), User: accountName(user)}
	if user.IsWellKnown(windows.WinLocalSystemSid) {
		who.Manage = true
		return who, nil
	}
	var gsid *windows.SID
	if group != "" {
		if s, _, _, err := windows.LookupSID("", group); err == nil {
			gsid = s
		}
	}
	// Administrators counts only when enabled (an elevated process; in a
	// filtered UAC token it is deny-only).
	if groups, err := tok.GetTokenGroups(); err == nil {
		for _, g := range groups.AllGroups() {
			if g.Attributes&windows.SE_GROUP_ENABLED == 0 || g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
				continue
			}
			if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || (gsid != nil && windows.EqualSid(g.Sid, gsid)) {
				who.Manage = true
				return who, nil
			}
		}
	}
	// the token only knows groups from logon time: someone added to the
	// group just now (by the installer) is found in the group itself
	if gsid != nil && groupHas(group, user) {
		who.Manage = true
	}
	return who, nil
}

func accountName(sid *windows.SID) string {
	if acc, dom, _, err := sid.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return sid.String()
}

// groupHas reports whether user is a direct member of the local group.
func groupHas(group string, user *windows.SID) bool {
	name, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return false
	}
	var buf *byte
	var read, total uint32
	var resume uintptr
	// level 0: LOCALGROUP_MEMBERS_INFO_0 (one SID pointer each)
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(name)), 0,
		uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if buf != nil {
		defer windows.NetApiBufferFree(buf)
	}
	if r != 0 {
		return false
	}
	for _, s := range unsafe.Slice((**windows.SID)(unsafe.Pointer(buf)), read) {
		if windows.EqualSid(s, user) {
			return true
		}
	}
	return false
}

// procInfo returns parent PID and creation time of a process (for the
// /v1/run check).
func procInfo(pid int) (winsvc.ProcInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return winsvc.ProcInfo{}, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	parent := -1
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if int(e.ProcessID) == pid {
			parent = int(e.ParentProcessID)
			break
		}
	}
	if parent < 0 {
		return winsvc.ProcInfo{}, fmt.Errorf("no process %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return winsvc.ProcInfo{}, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kt, ut windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kt, &ut); err != nil {
		return winsvc.ProcInfo{}, err
	}
	return winsvc.ProcInfo{Parent: parent, Created: time.Unix(0, created.Nanoseconds())}, nil
}

// allowUser creates the local manage group (if missing) and adds user to it
// ("shuntd-win allow-user [USER]", run by the installer as administrator).
func allowUser(group, user string) error {
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	gname, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return err
	}
	comment, _ := windows.UTF16PtrFromString("The Shunt: may change settings")
	// LOCALGROUP_INFO_1
	info := struct{ name, comment *uint16 }{gname, comment}
	r, _, _ := procNetLocalGroupAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0)
	const nerrGroupExists, errorAliasExists = 2223, 1379
	if r != 0 && r != nerrGroupExists && r != errorAliasExists {
		return fmt.Errorf("creating local group %q: %w", group, syscall.Errno(r))
	}
	if user == "" {
		return nil
	}
	uname, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	// LOCALGROUP_MEMBERS_INFO_3
	member := struct{ name *uint16 }{uname}
	r, _, _ = procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(gname)), 3, uintptr(unsafe.Pointer(&member)), 1)
	const errorMemberInAlias = 1378
	if r != 0 && r != errorMemberInAlias {
		return fmt.Errorf("adding %s to %q: %w", user, group, syscall.Errno(r))
	}
	fmt.Printf("%s may change The Shunt's settings (local group %q)\n", user, group)
	return nil
}
