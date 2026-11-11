package daemon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/miekg/dns"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/engine"
	"github.com/Bob-Nixkoenner/the_shunt/internal/nft"
	"github.com/Bob-Nixkoenner/the_shunt/internal/sockets"
)

const defenseUnsupported = ""

// defenseOptions: decoys listen on the physical uplink with the bypass mark
// (answers never enter a tunnel); blocks go into the nft table.
func (d *Daemon) defenseOptions() []defense.Option {
	return []defense.Option{
		defense.WithListen(defense.LinuxListen(d.defIface, engine.MarkBypass)),
		defense.WithBanHooks(d.nftBan, d.nftUnban),
	}
}

func (d *Daemon) nftBan(b defense.Ban) {
	a, err := netip.ParseAddr(b.Src)
	if err != nil || !d.defTableOn() {
		return
	}
	if err := nft.Apply(nft.BanScript(a, time.Until(b.Expires))); err != nil {
		d.Log.Warn("defense: could not block a source", "err", err)
	}
}

func (d *Daemon) nftUnban(b defense.Ban) {
	a, err := netip.ParseAddr(b.Src)
	if err != nil || !d.defTableOn() {
		return
	}
	if err := nft.Apply(nft.UnbanScript(a)); err != nil {
		d.Log.Debug("defense: unblock", "err", err)
	}
}

func (d *Daemon) defTableOn() bool {
	d.def.mu.Lock()
	defer d.def.mu.Unlock()
	return d.def.tableOn
}

// defenseTable installs or removes the nft table shunt_defense. A table that
// is already there keeps its bans.
func (d *Daemon) defenseTable(on bool) {
	d.def.mu.Lock()
	defer d.def.mu.Unlock()
	if on == d.def.tableOn {
		return
	}
	script := nft.DeleteDefenseScript()
	if on {
		script = nft.RenderDefense(nft.DefenseOpts{Log: true})
	}
	if err := nft.Apply(script); err != nil {
		d.Log.Warn("defense: nft table", "on", on, "err", err)
		return
	}
	d.def.tableOn = on
	if on {
		if len(d.def.never) > 0 {
			_ = nft.Apply(nft.NeverScript(d.def.never))
		}
		lctx, cancel := context.WithCancel(context.Background())
		d.def.logStop = cancel
		go d.defenseLog(lctx)
	} else if d.def.logStop != nil {
		d.def.logStop()
		d.def.logStop = nil
	}
}

func (d *Daemon) defenseNever(p []netip.Prefix) {
	d.def.mu.Lock()
	d.def.never = p
	on := d.def.tableOn
	d.def.mu.Unlock()
	if on {
		if err := nft.Apply(nft.NeverScript(p)); err != nil {
			d.Log.Debug("defense: never list", "err", err)
		}
	}
}

func (d *Daemon) newSensors() *defense.Sensors {
	return &defense.Sensors{
		M: d.def.m, Log: d.Log, Mark: engine.MarkBypass,
		Twins: &defense.TwinStore{Path: filepath.Join(d.defenseStateDir(), "twins.json")},
		DNS:   defense.DNSCheck{Reference: d.dnsReference},
	}
}

func (d *Daemon) defenseStateDir() string {
	if s, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":"); s != "" {
		return s
	}
	return d.defenseDir()
}

// dnsReference resolves name over DoH on the default route (through the
// tunnel when there is one), to an address literal so the local resolver
// is not involved.
func (d *Daemon) dnsReference(ctx context.Context, name string) ([]netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	cl := d.downloadClient()
	var last error
	for _, host := range []string{"1.1.1.1", "8.8.8.8"} {
		req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+"/dns-query", bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := cl.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("doh %d", resp.StatusCode)
			continue
		}
		var r dns.Msg
		if err := r.Unpack(body); err != nil {
			last = err
			continue
		}
		var out []netip.Addr
		for _, rr := range r.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, ok := netip.AddrFromSlice(a.A); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
		return out, nil
	}
	return nil, last
}

// defenseLog reads the NFLOG group of the defense table: first packets of
// new inbound connections. Connections to a port nothing listens on count
// as scan/brute-force attempts (Manager.Observe); connections to a port that
// really listens only go through the reputation check. Decoy ports are
// skipped (the decoys report their own hits). It runs until the table is
// removed. Limit: brute force on a real service is not seen this way.
func (d *Daemon) defenseLog(ctx context.Context) {
	nf, err := nflog.Open(&nflog.Config{Group: nft.DefenseLogGroup, Copymode: nflog.CopyPacket, Bufsize: 128})
	if err != nil {
		d.Log.Debug("defense: no packet log", "err", err)
		return
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var listen map[string]bool
	var at time.Time
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		src, proto, port, ok := defense.ParseLoggedPacket(*a.Payload)
		if !ok {
			return 0
		}
		if time.Since(at) > 5*time.Second || listen == nil {
			listen, at = listeningPorts(), time.Now()
		}
		for _, p := range d.def.m.Status().Decoys {
			if p == port && proto == "tcp" {
				return 0
			}
		}
		if listen[proto+"/"+fmt.Sprint(port)] {
			d.def.m.CheckPeer(src, port, proto)
		} else {
			d.def.m.Observe(src, port, proto, false)
		}
		return 0
	}, func(error) int { return 0 })
	if err != nil {
		return
	}
	<-ctx.Done()
}

func listeningPorts() map[string]bool {
	m := map[string]bool{}
	ss, err := sockets.ListListening()
	if err != nil {
		return m
	}
	for _, s := range ss {
		m[s.Proto+"/"+fmt.Sprint(s.Local.Port())] = true
	}
	return m
}

// defensePushPorts keeps the nft set of decoy ports (main table, inbound
// chain) equal to the ports that really listen. Cheap: runs every 5 s and
// only calls nft when the list changed or the main table was replaced.
func (d *Daemon) defensePushPorts() {
	if d.def.m == nil || !d.defTableOn() {
		return
	}
	ports := d.def.m.Status().Decoys
	d.def.mu.Lock()
	same := !d.def.needPush && fmt.Sprint(ports) == fmt.Sprint(d.def.portsSet)
	d.def.mu.Unlock()
	if same {
		return
	}
	if err := nft.Apply(nft.DecoyPortsScript(ports)); err != nil {
		// no inbound protection active: the set does not exist, nothing to do
		d.Log.Debug("defense: decoy port set", "err", err)
	}
	d.def.mu.Lock()
	d.def.portsSet, d.def.needPush = ports, false
	d.def.mu.Unlock()
}
