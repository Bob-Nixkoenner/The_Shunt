//go:build !linux

package defense

import "log/slog"

// Sensors is a stub: the sensors need Linux netlink and packet sockets.
type Sensors struct {
	M     *Manager
	Log   *slog.Logger
	DNS   DNSCheck
	Twins *TwinStore
	Mark  uint32
}

// SetEnv does nothing on this platform.
func (s *Sensors) SetEnv(Env) {}

// Stop does nothing on this platform.
func (s *Sensors) Stop() {}

// ProbeSoon does nothing on this platform.
func (s *Sensors) ProbeSoon() {}
