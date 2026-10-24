//go:build !windows

package main

import (
	"errors"
	"log"
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
func appSource(*api.Client, string) ui.AppSource { return nil }

const restartHint = "Check: journalctl -u shuntd -e"

const updatesSupported = true

// launcher is the program that starts apps in a route: the CLI.
func launcher(_, shunt string) string { return shunt }

// runIn: on Linux, `shunt run` does this.
func runIn(string, []string) error { return errors.New("use: shunt run --via ROUTE -- CMD") }

func runFailed(err error) { log.Print(err) }
