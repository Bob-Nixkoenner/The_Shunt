package winsplit

import "github.com/Bob-Nixkoenner/the_shunt/internal/winsplit/wfp"

// ExitGuard is one loopback address that belongs to the service (a SOCKS
// exit or tor.exe's SOCKS port), see wfp.ExitFilters.
type ExitGuard = wfp.ExitGuard

// SetExitGuard installs the WFP exit guard (report M-04): only the owners
// may accept on the addresses, and a taken address cannot be reached at all.
// An empty list removes it.
func SetExitGuard(gs []ExitGuard) error { return wfp.SetExitGuard(gs) }
