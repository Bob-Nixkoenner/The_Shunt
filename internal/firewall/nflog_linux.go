package firewall

import (
	"context"
	"strings"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
)

// Listen reads the NFLOG group of the waiting groups and reports each
// packet's group id (from the "ask:<id> " prefix) and owner uid (-1 if
// unknown) until ctx ends.
func Listen(ctx context.Context, seen func(id string, uid int)) error {
	nf, err := nflog.Open(&nflog.Config{Group: nft.AskLogGroup, Copymode: nflog.CopyMeta})
	if err != nil {
		return err
	}
	defer nf.Close()
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Prefix == nil {
			return 0
		}
		id, ok := strings.CutPrefix(strings.TrimSpace(*a.Prefix), "ask:")
		if !ok {
			return 0
		}
		uid := -1
		if a.UID != nil {
			uid = int(*a.UID)
		}
		seen(id, uid)
		return 0
	}, func(error) int { return 0 })
	if err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
