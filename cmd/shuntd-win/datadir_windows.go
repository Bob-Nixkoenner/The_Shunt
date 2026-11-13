package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Report H-04: C:\ProgramData lets every user create a folder there, and the
// creator owns it. A user who made "Shunt" before the installer or the
// service would stay its owner: icacls replaced the DACL, but an owner may
// always write the DACL again and could have put a shunt.toml or tunnel files
// there that the service (SYSTEM) then loads. So the data folder is created
// with its final security at once (owner Administrators, protected DACL:
// SYSTEM and Administrators only), and an existing folder owned by anyone
// else is moved aside and not used.
const dataDirSDDL = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// trustedOwner: SYSTEM, Administrators or TrustedInstaller.
func trustedOwner(sid *windows.SID) bool {
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if sid.IsWellKnown(w) {
			return true
		}
	}
	return sid.String() == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
}

// secureDataDir makes dir exist with owner Administrators and the protected
// DACL above. A folder owned by someone else is renamed to
// "<dir>.untrusted-<unix time>" first (its files are never read).
func secureDataDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return moveAside(dir, "not a plain folder")
		}
		cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("%s: reading the owner: %w", dir, err)
		}
		owner, _, err := cur.Owner()
		if err != nil {
			return fmt.Errorf("%s: reading the owner: %w", dir, err)
		}
		if !trustedOwner(owner) {
			if err := moveAside(dir, "owned by "+owner.String()); err != nil {
				return err
			}
		} else {
			o, _, _ := sd.Owner()
			dacl, _, _ := sd.DACL()
			return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				o, nil, dacl, nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafeSizeofSA)
	return windows.CreateDirectory(p, sa)
}

// movedAside: what moveAside did, logged again once the log file is open.
var movedAside []string

func moveAside(dir, why string) error {
	to := dir + ".untrusted-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.Rename(dir, to); err != nil {
		return fmt.Errorf("%s is %s and cannot be moved aside: %w", dir, why, err)
	}
	movedAside = append(movedAside, fmt.Sprintf("SECURITY: %s was %s: moved to %s, not used", dir, why, to))
	log.Print(movedAside[len(movedAside)-1])
	return nil
}

var unsafeSizeofSA = func() uintptr {
	var sa windows.SecurityAttributes
	return unsafe.Sizeof(sa)
}()
