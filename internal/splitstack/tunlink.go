package splitstack

import (
	"context"
	"errors"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tunOffset is headroom in front of every packet: the Linux TUN driver of
// wireguard-go needs room for its virtio header, wintun needs none.
const tunOffset = 16

// TunLink connects a wireguard-go TUN device (Windows: wintun via
// tun.CreateTUN) to the engine: two goroutines copy packets between the
// device and a gVisor channel endpoint. stop ends them; the caller closes
// the device afterwards (which ends a pending Read).
func TunLink(dev tun.Device, mtu int) (link stack.LinkEndpoint, stop func()) {
	ep := channel.New(1024, uint32(mtu), "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { // device -> stack
		n := max(dev.BatchSize(), 1)
		bufs, sizes := make([][]byte, n), make([]int, n)
		for i := range bufs {
			bufs[i] = make([]byte, tunOffset+mtu+64)
		}
		for ctx.Err() == nil {
			cnt, err := dev.Read(bufs, sizes, tunOffset)
			if err != nil && cnt == 0 {
				if errors.Is(err, tun.ErrTooManySegments) {
					continue // one oversized batch, not the end of the device
				}
				return // closed
			}
			for i := 0; i < cnt; i++ {
				p := bufs[i][tunOffset : tunOffset+sizes[i]]
				if len(p) == 0 {
					continue
				}
				proto := ipv4.ProtocolNumber
				if header.IPVersion(p) == header.IPv6Version {
					proto = ipv6.ProtocolNumber
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), p...))})
				ep.InjectInbound(proto, pkt)
				pkt.DecRef()
			}
		}
	}()
	go func() { // stack -> device
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			b := make([]byte, tunOffset+v.Size())
			copy(b[tunOffset:], v.AsSlice())
			v.Release()
			pkt.DecRef()
			dev.Write([][]byte{b}, tunOffset)
		}
	}()
	return ep, func() { cancel(); ep.Close() }
}
