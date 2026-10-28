//go:build windows

package i18n

import (
	"syscall"
	"unsafe"
)

// osLanguage: the user's display language ("de-DE") from GetUserDefaultLocaleName.
func osLanguage() string {
	p := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	n, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
