//go:build !windows

package main

import (
	"os"
	"syscall"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/ui"
)

const (
	defaultSocket = "/run/shunt/shuntd.sock"
	exeSuffix     = ""
)

// execSelf replaces this process with a fresh copy.
func execSelf(exe string, args []string) error { return syscall.Exec(exe, args, os.Environ()) }

func trayIcon(png []byte) []byte { return png }

// appSource: nil = the menu of the desktop (.desktop files).
func appSource(*api.Client) ui.AppSource { return nil }
