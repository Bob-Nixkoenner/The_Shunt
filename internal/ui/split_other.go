//go:build !windows

package ui

import "github.com/Bob-Nixkoenner/the_shunt/internal/argv"

// splitCmd splits a command typed in the UI (shell-like quoting).
func splitCmd(s string) ([]string, error) { return argv.Split(s) }
