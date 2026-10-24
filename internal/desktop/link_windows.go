package desktop

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// dirLink makes link a junction to the directory target. Symbolic links
// need administrator rights or developer mode on Windows, junctions do not.
// Deleting a junction (os.Remove, Explorer) leaves the target alone.
func dirLink(target, link string) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(link, 0o700); err != nil {
		return err
	}
	sub := utf16.Encode([]rune(`\??\` + target))
	prn := utf16.Encode([]rune(target))
	// REPARSE_DATA_BUFFER, MountPointReparseBuffer
	paths := (len(sub) + 1 + len(prn) + 1) * 2
	buf := make([]byte, 16+paths)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	le.PutUint16(buf[4:], uint16(8+paths))
	le.PutUint16(buf[8:], 0)                       // substitute name offset
	le.PutUint16(buf[10:], uint16(len(sub)*2))     // ... length
	le.PutUint16(buf[12:], uint16((len(sub)+1)*2)) // print name offset
	le.PutUint16(buf[14:], uint16(len(prn)*2))     // ... length
	for i, c := range sub {
		le.PutUint16(buf[16+i*2:], c)
	}
	for i, c := range prn {
		le.PutUint16(buf[16+(len(sub)+1+i)*2:], c)
	}
	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		os.Remove(link)
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		os.Remove(link)
		return err
	}
	var n uint32
	err = windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
	windows.CloseHandle(h)
	if err != nil {
		os.Remove(link)
		return &os.LinkError{Op: "junction", Old: target, New: link, Err: err}
	}
	return nil
}

func samePath(a, b string) bool {
	a = strings.TrimPrefix(a, `\??\`)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
