//go:build windows

package winsplit

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

type hklm struct{}

func (hklm) GetDWORD(key, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if err == registry.ErrNotExist {
			return 0, false, nil
		}
		return 0, false, err
	}
	return uint32(v), true, nil
}

func (hklm) SetDWORD(key, name string, v uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, v)
}

func (hklm) DeleteValue(key, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func (hklm) SubKeys(key string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

var quietStateDir string

// SetStateDir names the directory for the saved registry values.
func SetStateDir(dir string) { quietStateDir = dir }

func realQuietReg() *quietReg {
	return newQuietReg(hklm{}, filepath.Join(quietStateDir, "quiet-registry.json"))
}

// QuietSource switches LLMNR, mDNS and NetBIOS over TCP/IP off at the source
// (for the next boot; Windows sends them before the boot-time filters hold).
// Idempotent; call again when adapters appear.
func QuietSource() error {
	if quietStateDir == "" {
		return nil
	}
	return realQuietReg().apply()
}

// QuietSourceRestore puts the earlier registry values back.
func QuietSourceRestore() error {
	if quietStateDir == "" {
		return nil
	}
	return realQuietReg().restore()
}

func realNCSIHold() *quietReg {
	return newRegGuard(hklm{}, filepath.Join(quietStateDir, "ncsi-hold.json"), ncsiValues())
}

// NCSIBootHold sets the NCSI policy NoActiveProbe=1 for the next boot
// (at shutdown, kill switch on; see ncsihold.go).
func NCSIBootHold() error { return realNCSIHold().apply() }

// NCSIBootRelease takes the hold back if we set it (at start, killswitch-off,
// uninstall); a policy of the administrator stays.
func NCSIBootRelease() error { return realNCSIHold().restore() }

// NCSIHeld reports whether a boot hold set by us is still in place (call it
// before NCSIBootRelease: afterwards the answer is always false).
func NCSIHeld() bool { return len(realNCSIHold().load()) > 0 }

// NCSIRestart makes Windows' connectivity check read its settings again: it
// stops the process that hosts NlaSvc and starts netprofm and NlaSvc once
// more (see ncsihold.go for why a service restart is not enough). It leaves
// the process alone when other services live in it.
func NCSIRestart() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	// NlaSvc starts on demand and may be stopped while netprofm keeps the
	// shared host process (and the old policy) alive: ask both
	var pid uint32
	for _, name := range []string{"NlaSvc", "netprofm"} {
		s, err := m.OpenService(name)
		if err != nil {
			return "", err
		}
		st, err := s.Query()
		s.Close()
		if err != nil {
			return "", err
		}
		if st.ProcessId != 0 {
			pid = st.ProcessId
			break
		}
	}
	if pid != 0 {
		names, err := servicesInProcess(m, pid)
		if err != nil {
			return "", err
		}
		if !onlyNCSIServices(names) {
			return "", fmt.Errorf("the host of NlaSvc also runs %s: not stopped", strings.Join(names, ", "))
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", err
		}
		defer windows.CloseHandle(h)
		var buf [windows.MAX_PATH]uint16
		n := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil ||
			!strings.EqualFold(filepath.Base(windows.UTF16ToString(buf[:n])), "svchost.exe") {
			return "", fmt.Errorf("process %d is not svchost.exe: not stopped", pid)
		}
		if err := windows.TerminateProcess(h, 1); err != nil {
			return "", err
		}
	}
	var last error
	for _, name := range []string{"netprofm", "NlaSvc"} {
		if err := startService(m, name); err != nil {
			last = err
		}
	}
	info := fmt.Sprintf("host process %d", pid)
	if nla, err := m.OpenService("NlaSvc"); err == nil {
		if now, err := nla.Query(); err == nil {
			info += fmt.Sprintf(" -> %d", now.ProcessId)
		}
		nla.Close()
	}
	return info, last
}

func servicesInProcess(m *mgr.Mgr, pid uint32) ([]string, error) {
	all, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var in []string
	for _, n := range all {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		if st, err := s.Query(); err == nil && st.ProcessId == pid {
			in = append(in, n)
		}
		s.Close()
	}
	return in, nil
}

// startService starts a service unless it already runs (the SCM may have
// restarted it by its recovery action); a few tries, the old process is
// still going down.
func startService(m *mgr.Mgr, name string) error {
	var err error
	for range 10 {
		var s *mgr.Service
		if s, err = m.OpenService(name); err == nil {
			st, qerr := s.Query()
			if qerr == nil && st.State == windows.SERVICE_RUNNING {
				s.Close()
				return nil
			}
			err = s.Start()
			s.Close()
			if err == nil || err == windows.ERROR_SERVICE_ALREADY_RUNNING {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return err
}
