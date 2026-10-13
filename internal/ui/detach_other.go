//go:build !linux

package ui

import "os/exec"

func detach(*exec.Cmd) {}
