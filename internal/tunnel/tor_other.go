//go:build !linux && !windows

package tunnel

import (
	"errors"
	"log/slog"
	"net"
	"time"
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

// QueryCircuit is not implemented on this platform: no circuit is shown.
func QueryCircuit(func(...string) ([]string, error), bool, time.Time) (*TorCircuit, error) {
	return nil, nil
}

// ControlExchange is not implemented on this platform.
func ControlExchange(net.Conn, []byte, []string) ([]string, error) {
	return nil, errors.New("not supported")
}
