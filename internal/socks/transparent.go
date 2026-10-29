package socks

import (
	"context"
	"io"
	"net"
	"net/netip"
)

// Transparent serves connections that nft redirected to l (REDIRECT, so
// the original destination is still known) and hands each to Handle with
// the destination. Connections made straight to the port are refused.
type Transparent struct {
	// Handle serves one connection; it owns c and must close it.
	Handle func(ctx context.Context, c net.Conn, dst netip.AddrPort)
}

// Serve accepts on l until it is closed.
func (t *Transparent) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if isClosed(err) {
				return nil
			}
			return err
		}
		go func() {
			dst, err := originalDst(c)
			if err != nil {
				c.Close()
				return
			}
			t.Handle(context.Background(), c, dst)
		}()
	}
}

// Pipe copies both ways until both directions ended, then closes both.
func Pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}
