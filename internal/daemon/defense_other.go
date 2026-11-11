//go:build !linux

package daemon

import (
	"net/netip"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
)

const defenseUnsupported = "the defense is Linux-only for now"

func (d *Daemon) defenseOptions() []defense.Option { return nil }
func (d *Daemon) newSensors() *defense.Sensors     { return &defense.Sensors{M: d.def.m} }
func (d *Daemon) defenseTable(bool)                {}
func (d *Daemon) defenseNever([]netip.Prefix)      {}

func (d *Daemon) defensePushPorts() {}
