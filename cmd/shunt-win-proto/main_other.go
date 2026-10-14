//go:build !windows

// shunt-win-proto is Windows-only; see main_windows.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "shunt-win-proto runs on Windows only")
	os.Exit(1)
}
