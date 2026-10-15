//go:build !windows

package main

import (
	"os"
	"syscall"
)

const (
	defaultSocket = "/run/shunt/shuntd.sock"
	exeSuffix     = ""
)

// execSelf replaces this process with a fresh copy.
func execSelf(exe string, args []string) error { return syscall.Exec(exe, args, os.Environ()) }

func trayIcon(png []byte) []byte { return png }
