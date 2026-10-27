//go:build !linux

package daemon

import "errors"

// CgroupExec is Linux only.
func CgroupExec([]string) error { return errors.New("cgexec needs Linux") }
