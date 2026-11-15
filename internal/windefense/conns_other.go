//go:build !windows

package windefense

// no connection table to read here (the tests feed a poller directly)
var listConns func() ([]TCPConn, error)

func processName(uint32) string { return "" }
