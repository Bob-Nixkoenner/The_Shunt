// mkversion writes a Windows resource object (.syso) with a VERSIONINFO block, so that the
// .exe files show a ProductVersion/FileVersion (Explorer properties, the lab analyzer, installers).
// No external tool: the COFF object is written by hand. packaging/windows/build.sh puts the result
// next to the main package for the build and removes it afterwards.
//
//	go run ./packaging/windows/mkversion <version> <description> <exe name> out.syso
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"regexp"
	"strconv"
	"unicode/utf16"
)

var le = binary.LittleEndian

func u16(s string) []byte { // zero-terminated UTF-16LE
	b := new(bytes.Buffer)
	for _, c := range utf16.Encode([]rune(s + "\x00")) {
		binary.Write(b, le, c)
	}
	return b.Bytes()
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// node is one VERSIONINFO structure: length, value length, type, key, value, children (all 4-aligned).
func node(key string, val []byte, valLen int, typ int, children ...[]byte) []byte {
	hdr := make([]byte, 6)
	le.PutUint16(hdr[2:], uint16(valLen))
	le.PutUint16(hdr[4:], uint16(typ))
	out := append(hdr, u16(key)...)
	out = pad4(out)
	out = append(out, val...)
	out = pad4(out)
	for _, c := range children {
		out = append(out, c...)
	}
	le.PutUint16(out, uint16(len(out)))
	return out
}

func str(k, v string) []byte { return node(k, u16(v), len(u16(v))/2, 1) }

func main() {
	if len(os.Args) != 5 {
		log.Fatal("usage: mkversion <version> <description> <exe name> out.syso")
	}
	version, desc, exe, out := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	nums := [4]uint16{}
	if m := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`).FindStringSubmatch(version); m != nil {
		for i := 0; i < 3; i++ {
			n, _ := strconv.Atoi(m[i+1])
			nums[i] = uint16(n)
		}
	}
	ms := uint32(nums[0])<<16 | uint32(nums[1])
	ls := uint32(nums[2])<<16 | uint32(nums[3])
	fixed := new(bytes.Buffer)
	for _, v := range []uint32{0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3f, 0, 0x40004, 1, 0, 0, 0} {
		binary.Write(fixed, le, v)
	}
	table := node("040904b0", nil, 0, 1,
		str("CompanyName", "The Shunt"), str("FileDescription", desc), str("FileVersion", version),
		str("InternalName", exe), str("OriginalFilename", exe), str("ProductName", "The Shunt"),
		str("ProductVersion", version))
	trans := new(bytes.Buffer)
	binary.Write(trans, le, uint32(0x04b00409))
	info := node("VS_VERSION_INFO", fixed.Bytes(), fixed.Len(), 0,
		node("StringFileInfo", nil, 0, 1, table),
		node("VarFileInfo", nil, 0, 1, node("Translation", trans.Bytes(), 4, 0)))

	// .rsrc: type dir (RT_VERSION=16) -> name dir (1) -> language dir (0x409) -> data entry -> data
	rs := new(bytes.Buffer)
	dir := func(id uint32, sub uint32) {
		binary.Write(rs, le, [4]uint32{0, 0, 0, 1 << 16}) // characteristics, time, version, 0 named / 1 id entry
		binary.Write(rs, le, [2]uint32{id, sub})
	}
	dir(16, 0x80000000|24)
	dir(1, 0x80000000|48)
	dir(0x409, 72)
	dataOff := 72 + 16 // entry (16 bytes), then data
	binary.Write(rs, le, [4]uint32{uint32(dataOff), uint32(len(info)), 0, 0})
	rs.Write(info)
	raw := pad4(rs.Bytes())

	// COFF object: header, one section (.rsrc), relocation for the data RVA, symbol table
	const hdr, sec = 20, 40
	secOff := hdr + sec
	relOff := secOff + len(raw)
	symOff := relOff + 10
	o := new(bytes.Buffer)
	binary.Write(o, le, struct {
		Machine          uint16
		Sections         uint16
		Time             uint32
		SymPtr, SymCount uint32
		OptSize, Flags   uint16
	}{0x8664, 1, 0, uint32(symOff), 1, 0, 0})
	name := [8]byte{}
	copy(name[:], ".rsrc")
	binary.Write(o, le, name)
	binary.Write(o, le, [6]uint32{0, 0, uint32(len(raw)), uint32(secOff), uint32(relOff), 0})
	binary.Write(o, le, [2]uint16{1, 0})
	binary.Write(o, le, uint32(0x40000040)) // initialised data, read
	o.Write(raw)
	binary.Write(o, le, uint32(72)) // relocation at the OffsetToData field of the data entry
	binary.Write(o, le, uint32(0))  // symbol 0
	binary.Write(o, le, uint16(3))  // IMAGE_REL_AMD64_ADDR32NB
	binary.Write(o, le, struct {    // symbol: .rsrc, value 0, section 1, type 0, static, no aux
		Name    [8]byte
		Value   uint32
		Section int16
		Type    uint16
		Class   uint8
		Aux     uint8
	}{name, 0, 1, 0, 3, 0})
	binary.Write(o, le, uint32(4)) // string table (empty)
	if err := os.WriteFile(out, o.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
