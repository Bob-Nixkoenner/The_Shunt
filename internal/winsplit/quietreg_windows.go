//go:build windows

package winsplit

import (
	"path/filepath"

	"golang.org/x/sys/windows/registry"
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
