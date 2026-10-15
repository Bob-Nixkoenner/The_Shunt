package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
	"github.com/Bob-Nixkoenner/the_shunt/internal/winapps"
)

var (
	defaultSocket = filepath.Join(os.Getenv("ProgramData"), "Shunt", "shuntd.sock")
	exeSuffix     = ".exe"
)

// execSelf starts a fresh copy and ends this process (Windows has no exec).
func execSelf(exe string, args []string) error {
	cmd := exec.Command(exe, args[1:]...)
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// trayIcon wraps the PNG in an ICO container (the Windows tray wants .ico;
// Vista and later accept PNG data inside it).
func trayIcon(p []byte) []byte {
	cfg, err := png.DecodeConfig(bytes.NewReader(p))
	if err != nil {
		return p
	}
	var b bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&b, le, [3]uint16{0, 1, 1}) // reserved, type icon, one image
	dim := func(n int) byte {
		if n >= 256 {
			return 0
		}
		return byte(n)
	}
	b.Write([]byte{dim(cfg.Width), dim(cfg.Height), 0, 0})
	_ = binary.Write(&b, le, [2]uint16{1, 32}) // planes, bits per pixel
	_ = binary.Write(&b, le, uint32(len(p)))
	_ = binary.Write(&b, le, uint32(22)) // data offset
	b.Write(p)
	return b.Bytes()
}

// appSource: programs with rules instead of the Linux menu.
func appSource(c *api.Client) ui.AppSource { return &winapps.Source{Client: c} }

var restartHint = "Check: " + filepath.Join(os.Getenv("ProgramData"), "Shunt", "shuntd.log")

const updatesSupported = false
