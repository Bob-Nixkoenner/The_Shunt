package defense

import (
	"context"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ifaceSettle is how long the watch waits after a link appeared before it
// reads the driver from sysfs (the driver binds after the device registers).
const ifaceSettle = 1500 * time.Millisecond

// ifaceState returns the watch shared by all SetEnv rounds, so "present at
// start" means the first start of the Sensors, not each network change.
func (s *Sensors) ifaceState() *ifaceWatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ifw == nil {
		var names []string
		if ls, err := netlink.LinkList(); err == nil {
			for _, l := range ls {
				names = append(names, l.Attrs().Name)
			}
		}
		s.ifw = newIfaceWatch(names)
	}
	return s.ifw
}

// newIface reports interfaces that were not there at start (netlink
// RTM_NEWLINK) and a default route that goes over one. Passive.
func (s *Sensors) newIface(ctx context.Context) {
	w := s.ifaceState()
	links := make(chan netlink.LinkUpdate, 32)
	routes := make(chan netlink.RouteUpdate, 32)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribeWithOptions(links, done, netlink.LinkSubscribeOptions{ErrorCallback: func(error) {}}); err != nil {
		s.log().Debug("defense: no link events", "err", err)
		return
	}
	if err := netlink.RouteSubscribeWithOptions(routes, done, netlink.RouteSubscribeOptions{ErrorCallback: func(error) {}}); err != nil {
		routes = nil // link events alone still help
	}
	pending := map[string]time.Time{} // new name -> first seen
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-links:
			if !ok {
				return
			}
			if u.Header.Type != unix.RTM_NEWLINK || u.Link == nil {
				continue
			}
			if n := u.Link.Attrs().Name; w.IsNew(n) && len(pending) < 16 {
				if _, seen := pending[n]; !seen {
					pending[n] = time.Now()
				}
			}
		case u, ok := <-routes:
			if !ok {
				routes = nil
				continue
			}
			if u.Type != unix.RTM_NEWROUTE || (u.Dst != nil && !isZeroNet(u.Dst.IP, u.Dst.Mask)) {
				continue
			}
			l, err := netlink.LinkByIndex(u.LinkIndex)
			if err != nil {
				continue
			}
			n := l.Attrs().Name
			if !w.IsNew(n) {
				continue
			}
			if ev, hit := w.DefaultRoute(n, ClassifyIface("/sys", n)); hit {
				s.emit(FeatNewIface, ev)
			}
		case <-tick.C:
			for n, t := range pending {
				if time.Since(t) < ifaceSettle {
					continue
				}
				delete(pending, n)
				if ev, hit := w.Link(n, ClassifyIface("/sys", n)); hit {
					s.emit(FeatNewIface, ev)
				}
			}
		}
	}
}

func isZeroNet(ip []byte, mask []byte) bool {
	for _, b := range mask {
		if b != 0 {
			return false
		}
	}
	return true
}
