//go:build !linux && !windows

package tunnel

import (
	"errors"
	"log/slog"
)

// StartTor is not implemented on this platform yet.
func StartTor(TorSpec, *slog.Logger, func()) (Device, error) {
	return nil, errors.New("Tor tunnels are not supported on this platform yet")
}

// ptDirs: no extra search directories here, only PATH is used.
var ptDirs []string

// TorCircuit is the circuit a Tor tunnel's traffic currently uses (see tor_circuit.go).
type TorCircuit struct {
	Hops    int    `json:"hops"`
	Bridge  bool   `json:"bridge,omitempty"`
	Country string `json:"country,omitempty"`
	Relay   string `json:"relay,omitempty"`
	IP      string `json:"ip,omitempty"`
}
