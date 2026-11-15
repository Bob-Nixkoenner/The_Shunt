//go:build !windows

package windefense

import (
	"log/slog"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

// newSensors: the table watch is Windows only (tests on other systems run
// without sensors).
func newSensors(*defense.Manager, *slog.Logger, string) sensors { return nil }
