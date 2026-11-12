// Package systemd holds the systemd unit files; the Go file here is only
// the test that checks shuntd.service against the syscalls shuntd can make.
// This file keeps the directory a buildable package, so "go build ./..."
// does not stop on a directory with test files only.
package systemd
