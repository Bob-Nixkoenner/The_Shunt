//go:build !linux

package daemon

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

const defenseUnsupported = "the defense is Linux-only for now"

func (d *Daemon) defenseOptions() []defense.Option { return nil }
func (d *Daemon) newSensors() *defense.Sensors     { return &defense.Sensors{M: d.def.m} }
func (d *Daemon) defenseTable(bool)                {}
func (d *Daemon) defenseNever([]netip.Prefix)      {}

func (d *Daemon) defensePushPorts() {}

// defenseConnLoop: no socket listing on this platform, so no beacon or
// first-contact detection (DNS tunnel detection works everywhere).
func (d *Daemon) defenseConnLoop(context.Context) {}

// defenseTLSLoop: the certificate check is Linux-only for now.
func (d *Daemon) defenseTLSLoop(context.Context) {}

// outsideHTTP: no packet marks here; the check goes out the normal way.
func (d *Daemon) outsideHTTP(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{Timeout: defense.OutsideTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}}
}
