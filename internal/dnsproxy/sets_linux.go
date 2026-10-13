package dnsproxy

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
)

// NftSets writes to sets of an inet table via netlink (no fork per answer).
type NftSets struct {
	Table string
}

// Add implements SetWriter.
func (n NftSets) Add(set string, addrs []netip.Addr, timeout time.Duration) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Name: n.Table, Family: nftables.TableFamilyINet}
	s, err := c.GetSetByName(t, set)
	if err != nil {
		return fmt.Errorf("set %s: %w", set, err)
	}
	elems := make([]nftables.SetElement, len(addrs))
	for i, a := range addrs {
		elems[i] = nftables.SetElement{Key: a.AsSlice(), Timeout: timeout}
	}
	if err := c.SetAddElements(s, elems); err != nil {
		return err
	}
	return c.Flush()
}
