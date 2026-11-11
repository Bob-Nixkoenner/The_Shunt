//go:build linux

package evidence

import (
	"context"
	"errors"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// CaptureSupported says whether this platform has a packet source.
const CaptureSupported = true

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// RunControl reads the control frames (ControlFilter, incoming only) of one
// interface and hands them to c until ctx ends. Passive; needs CAP_NET_RAW.
// A failure to open the socket ends it quietly (returns the error).
func RunControl(ctx context.Context, iface string, c *Capture) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	raw, err := ControlFilterRaw()
	if err != nil {
		return err
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	// the filter is attached before the socket is bound: nothing outside it
	// is ever queued
	fp := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: link.Attrs().Index}); err != nil {
		return err
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue // our own frames are not recorded
		}
		c.Packet(IfControl, buf[:n], n)
	}
	return nil
}
