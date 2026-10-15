package winapps

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// shortcut builds a minimal .lnk with a LinkInfo block.
func shortcut(path string, unicode bool) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, 0x4C)
	le.PutUint32(hdr, 0x4C)
	le.PutUint32(hdr[0x14:], 2) // HasLinkInfo only
	var li []byte
	if unicode {
		li = make([]byte, 0x24)
		le.PutUint32(li[4:], 0x24)
	} else {
		li = make([]byte, 0x1C)
		le.PutUint32(li[4:], 0x1C)
	}
	le.PutUint32(li[8:], 1)
	if unicode {
		le.PutUint32(li[0x1C:], uint32(len(li)))
		for _, c := range utf16.Encode([]rune(path)) {
			li = binary.LittleEndian.AppendUint16(li, c)
		}
		li = append(li, 0, 0)
	} else {
		le.PutUint32(li[0x10:], uint32(len(li)))
		li = append(append(li, path...), 0)
		le.PutUint32(li[0x18:], uint32(len(li)))
		li = append(li, 0)
	}
	le.PutUint32(li, uint32(len(li)))
	return append(hdr, li...)
}

func TestLnkTarget(t *testing.T) {
	for _, u := range []bool{false, true} {
		got, err := lnkTarget(shortcut(`C:\Program Files\Mozilla Firefox\firefox.exe`, u))
		if err != nil || got != `C:\Program Files\Mozilla Firefox\firefox.exe` {
			t.Errorf("unicode=%v: %q %v", u, got, err)
		}
	}
	if _, err := lnkTarget([]byte("nope")); err == nil {
		t.Error("garbage accepted")
	}
	b := shortcut(`C:\x.exe`, false)
	for n := 0; n < len(b); n++ { // truncated files must not panic
		_, _ = lnkTarget(b[:n])
	}
}
