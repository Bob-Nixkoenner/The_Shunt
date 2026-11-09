//go:build windows && !amd64 && !arm64

package winsplit

import (
	"errors"
	"time"
)

// DNSWatch needs the 64-bit ETW structures (dnsetw_windows.go).
type DNSWatch struct{}

func StartDNSWatch(func(pid uint32) string, func(string)) (*DNSWatch, error) {
	return nil, errors.New("not available on this platform")
}

func (*DNSWatch) Close()                            {}
func (*DNSWatch) Askers(string, time.Time) []string { return nil }
