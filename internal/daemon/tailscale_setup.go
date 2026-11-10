package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// TailscaleDropIn is the systemd drop-in that lets shuntd run Tailscale
// tunnels (packaging/systemd/shuntd-tailscale.conf, same text). The base
// unit's hardening forbids network namespaces, which a Tailscale tunnel
// needs; it is opt-in so a machine without Tailscale keeps the tighter unit.
const TailscaleDropIn = `# The Shunt: lets shuntd run Tailscale tunnels (systemd drop-in, not active by
# default). Install it with: sudo shuntd setup-tailscale   (undo: --off)
# It goes to /etc/systemd/system/shuntd.service.d/50-tailscale.conf.
#
# Why each line (internal/tunnel/tailscale_linux.go):
# - a Tailscale tunnel runs tailscaled in a network namespace of its own;
#   creating it (unshare) and entering it (setns) need CAP_SYS_ADMIN and are
#   refused by RestrictNamespaces=yes. The empty line resets the base unit's
#   "yes", the next allows network namespaces only.
# - tailscaled uses raw and packet sockets (disco, ICMP): CAP_NET_RAW, AF_PACKET.
# Everything else of the base unit's hardening stays.
[Service]
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_RAW
RestrictNamespaces=
RestrictNamespaces=net
RestrictAddressFamilies=AF_PACKET
`

// TailscaleDropInPath is where SetupTailscale puts the drop-in.
var TailscaleDropInPath = "/etc/systemd/system/shuntd.service.d/50-tailscale.conf"

// systemctl runs systemctl (a variable for tests).
var systemctl = func(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %v: %s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

// SetupTailscale installs (off false) or removes the drop-in, then reloads
// systemd and restarts shuntd so it takes effect. changed reports whether
// the file was written or removed (false: already as wanted, nothing done).
func SetupTailscale(off bool) (changed bool, err error) {
	have, rerr := os.ReadFile(TailscaleDropInPath)
	switch {
	case off && errors.Is(rerr, os.ErrNotExist):
		return false, nil
	case off:
		if err := os.Remove(TailscaleDropInPath); err != nil {
			return false, err
		}
	case rerr == nil && string(have) == TailscaleDropIn:
		return false, nil
	default:
		if err := os.MkdirAll(filepath.Dir(TailscaleDropInPath), 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(TailscaleDropInPath, []byte(TailscaleDropIn), 0o644); err != nil {
			return false, err
		}
	}
	if err := systemctl("daemon-reload"); err != nil {
		return true, err
	}
	// restart only a running shuntd (try-restart): a stopped one picks the
	// drop-in up at its next start
	return true, systemctl("try-restart", "shuntd.service")
}

// tailscaleNeedsSetup tells whether a Tailscale tunnel failed only because
// the service may not create network namespaces (the drop-in is missing).
// (tunnel.StartTailscale wraps it as "network namespace: …").
func tailscaleNeedsSetup(err error) bool {
	return err != nil && errors.Is(err, syscall.EPERM) && strings.Contains(err.Error(), "network namespace")
}
