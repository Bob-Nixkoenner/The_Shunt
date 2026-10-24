package ui

import "golang.org/x/sys/windows"

// splitCmd splits a command typed in the UI the way Windows programs split
// their command line (backslashes in paths stay).
func splitCmd(s string) ([]string, error) { return windows.DecomposeCommandLine(s) }
