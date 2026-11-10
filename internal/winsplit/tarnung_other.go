//go:build !windows

package winsplit

// RealTarn is not available here (Windows only).
func RealTarn() *Tarn { return nil }
