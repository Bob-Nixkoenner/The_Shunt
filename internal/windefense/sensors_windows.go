//go:build windows

package windefense

import (
	"log/slog"
	"path/filepath"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

func newSensors(m *defense.Manager, log *slog.Logger, dir string) sensors {
	s := &defense.Sensors{M: m, Log: log}
	if dir != "" {
		s.Twins = &defense.TwinStore{Path: filepath.Join(dir, "twins.json")}
	}
	return s
}
