//go:build !windows

// Command shuntd-win is the Shunt service for Windows.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "shuntd-win runs on Windows only (Linux: shuntd)")
	os.Exit(2)
}
