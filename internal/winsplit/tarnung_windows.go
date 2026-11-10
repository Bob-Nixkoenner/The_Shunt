//go:build windows

package winsplit

import (
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

func init() { tunnelConnName = AdapterName }

type valHKLM struct{}

func (valHKLM) Get(key, name string) (RegVal, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return RegVal{}, false, nil
		}
		return RegVal{}, false, err
	}
	defer k.Close()
	_, typ, err := k.GetValue(name, nil)
	if err != nil {
		if err == registry.ErrNotExist {
			return RegVal{}, false, nil
		}
		return RegVal{}, false, err
	}
	switch typ {
	case registry.DWORD:
		v, _, err := k.GetIntegerValue(name)
		return RegVal{Kind: "dword", D: uint32(v)}, err == nil, err
	case registry.BINARY:
		v, _, err := k.GetBinaryValue(name)
		return RegVal{Kind: "bin", B: v}, err == nil, err
	default:
		v, _, err := k.GetStringValue(name)
		return RegVal{Kind: "sz", S: v}, err == nil, err
	}
}

func (valHKLM) Set(key, name string, v RegVal) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	switch v.Kind {
	case "dword":
		return k.SetDWordValue(name, v.D)
	case "bin":
		return k.SetBinaryValue(name, v.B)
	default:
		return k.SetStringValue(name, v.S)
	}
}

func (valHKLM) Delete(key, name string) error { return hklm{}.DeleteValue(key, name) }

func (valHKLM) SubKeys(key string) ([]string, error) { return hklm{}.SubKeys(key) }

// restartNIC switches the adapter off and on again (a new NetworkAddress is
// read when it starts); netsh takes the connection name, any language.
func restartNIC(conn string) error {
	if conn == "" {
		return nil
	}
	if out, err := exec.Command("netsh", "interface", "set", "interface", "name="+conn, "admin=disabled").CombinedOutput(); err != nil {
		return &execErr{err, out}
	}
	time.Sleep(time.Second)
	if out, err := exec.Command("netsh", "interface", "set", "interface", "name="+conn, "admin=enabled").CombinedOutput(); err != nil {
		return &execErr{err, out}
	}
	return nil
}

type execErr struct {
	err error
	out []byte
}

func (e *execErr) Error() string { return e.err.Error() + ": " + string(e.out) }

// RealTarn is the disguise on this machine; its state lives in the state
// directory (SetStateDir).
func RealTarn() *Tarn {
	return NewTarn(valHKLM{}, filepath.Join(quietStateDir, "tarnung.json"), restartNIC)
}
