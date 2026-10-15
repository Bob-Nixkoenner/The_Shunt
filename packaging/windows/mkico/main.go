// mkico writes the Shunt icon as a Windows .ico (PNG inside), used by
// packaging/windows/build.sh for the Start menu shortcut.
package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"log"
	"os"

	"github.com/Bob-Nixkoenner/the_shunt/internal/desktopapp"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: mkico out.ico")
	}
	p := desktopapp.Icon(desktopapp.OK)
	cfg, err := png.DecodeConfig(bytes.NewReader(p))
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&b, le, [3]uint16{0, 1, 1})
	b.Write([]byte{byte(cfg.Width), byte(cfg.Height), 0, 0})
	_ = binary.Write(&b, le, [2]uint16{1, 32})
	_ = binary.Write(&b, le, uint32(len(p)))
	_ = binary.Write(&b, le, uint32(22))
	b.Write(p)
	if err := os.WriteFile(os.Args[1], b.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
