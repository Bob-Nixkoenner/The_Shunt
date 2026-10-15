package winapps

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Running returns the executable paths of the running programs (one per
// process, as far as they may be read).
func Running() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	seen := map[string]bool{}
	var out []string
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			if p := windows.UTF16ToString(buf[:n]); !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		windows.CloseHandle(h)
	}
	return out
}
