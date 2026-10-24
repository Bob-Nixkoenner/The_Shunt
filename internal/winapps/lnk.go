package winapps

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// lnkTarget reads the target path of a Windows shortcut (.lnk, MS-SHLLINK)
// without COM: from the LinkInfo block, which holds the local path of the
// target for ordinary program shortcuts. Shortcuts without one (Store apps,
// shell items) return an error.
func lnkTarget(b []byte) (string, error) {
	le := binary.LittleEndian
	if len(b) < 0x4C || le.Uint32(b) != 0x4C {
		return "", errors.New("not a shortcut")
	}
	flags := le.Uint32(b[0x14:])
	pos := 0x4C
	if flags&1 != 0 { // HasLinkTargetIDList
		if pos+2 > len(b) {
			return "", errors.New("short")
		}
		pos += 2 + int(le.Uint16(b[pos:]))
	}
	if flags&2 == 0 { // HasLinkInfo
		return "", errors.New("no link info")
	}
	li := b[min(pos, len(b)):]
	if len(li) < 0x1C || int(le.Uint32(li)) > len(li) {
		return "", errors.New("short link info")
	}
	li = li[:le.Uint32(li)]
	hdr := le.Uint32(li[4:])
	if le.Uint32(li[8:])&1 == 0 { // VolumeIDAndLocalBasePath
		return "", errors.New("no local path")
	}
	cstr := func(off uint32) string {
		if int(off) >= len(li) {
			return ""
		}
		end := int(off)
		for end < len(li) && li[end] != 0 {
			end++
		}
		return string(li[off:end])
	}
	ustr := func(off uint32) string {
		var u []uint16
		for i := int(off); i+1 < len(li); i += 2 {
			c := le.Uint16(li[i:])
			if c == 0 {
				break
			}
			u = append(u, c)
		}
		return string(utf16.Decode(u))
	}
	var base, suffix string
	if hdr >= 0x24 && len(li) >= 0x24 { // Unicode offsets present
		base, suffix = ustr(le.Uint32(li[0x1C:])), ""
		if off := le.Uint32(li[0x20:]); off != 0 {
			suffix = ustr(off)
		}
	} else {
		base, suffix = cstr(le.Uint32(li[0x10:])), cstr(le.Uint32(li[0x18:]))
	}
	if base == "" {
		return "", errors.New("empty target")
	}
	return base + suffix, nil
}

// StartMenuProgram is an installed program found through a Start menu shortcut.
type StartMenuProgram struct {
	Name string // shortcut name, "Mozilla Firefox"
	Path string // target, "C:\Program Files\Mozilla Firefox\firefox.exe"
}

// StartMenu lists the programs with a shortcut in the all-users and the
// user's Start menu.
func StartMenu() []StartMenuProgram {
	var out []StartMenuProgram
	for _, root := range []string{
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`),
		filepath.Join(os.Getenv("AppData"), `Microsoft\Windows\Start Menu\Programs`),
	} {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() && d.Name() == MenuFolder {
				return filepath.SkipDir // our launchers start shunt-desktop
			}
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".lnk") {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil {
				if t, err := lnkTarget(b); err == nil && strings.EqualFold(filepath.Ext(t), ".exe") {
					out = append(out, StartMenuProgram{Name: strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)), Path: t})
				}
			}
			return nil
		})
	}
	return out
}
