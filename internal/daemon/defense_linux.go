package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

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
	if p, err := netip.ParsePrefix(b.Src); err == nil { // a whole range (exposed networks)
		if d.defTableOn() {
			if err := nft.Apply(nft.BanRangeScript(p, time.Until(b.Expires))); err != nil {
				d.Log.Warn("defense: could not block a range", "err", err)
			}
		}
		return
	}
	a, err := netip.ParseAddr(b.Src)
	if err != nil || !d.defTableOn() {
		return
	}
	if err := nft.Apply(nft.BanScript(a, time.Until(b.Expires))); err != nil {
		d.Log.Warn("defense: could not block a source", "err", err)
	}
}

func (d *Daemon) nftUnban(b defense.Ban) {
	if p, err := netip.ParsePrefix(b.Src); err == nil {
		if d.defTableOn() {
			if err := nft.Apply(nft.UnbanRangeScript(p)); err != nil {
				d.Log.Debug("defense: unblock range", "err", err)
			}
		}
		return
	}
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
		script = nft.RenderDefense(nft.DefenseOpts{Log: true, ConnLog: true})
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
		// a reader of an earlier table must have closed its NFLOG socket
		// before a new one binds the same group
		d.def.logWG.Wait()
		lctx, cancel := context.WithCancel(context.Background())
		d.def.logStop = cancel
		d.def.logWG.Add(2)
		go func() { defer d.def.logWG.Done(); d.defenseLog(lctx) }()
		go func() { defer d.def.logWG.Done(); d.defenseConnLog(lctx) }()
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
	st := &logState{}
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		// runs in the NFLOG reader's goroutine on packets from strangers:
		// a bug here must cost one packet, not the daemon
		defense.Guard(d.Log, "inbound packet log", func() { d.defenseLogPacket(st, a) })
		return 0
	}, func(error) int { return 0 })
	if err != nil {
		return
	}
	<-ctx.Done()
}

// logState is the listening-port list defenseLogPacket keeps between
// packets (read again every 5 s). Only the NFLOG reader goroutine uses it.
type logState struct {
	listen map[string]bool
	at     time.Time
}

// defenseLogPacket handles one logged inbound packet (see defenseLog).
func (d *Daemon) defenseLogPacket(st *logState, a nflog.Attribute) {
	if a.Payload == nil {
		return
	}
	src, proto, port, ok := defense.ParseLoggedPacket(*a.Payload)
	if !ok {
		return
	}
	if time.Since(st.at) > 5*time.Second || st.listen == nil {
		st.listen, st.at = listeningPorts(), time.Now()
	}
	d.evidencePacket(*a.Payload, proto, port, st.listen)
	for _, p := range d.def.m.DecoyPorts() {
		if p == port && proto == "tcp" {
			return
		}
	}
	if st.listen[proto+"/"+fmt.Sprint(port)] {
		d.def.m.CheckPeer(src, port, proto)
	} else {
		d.def.m.ObserveState(src, port, proto, defense.StateS0) // logged before the drop: nothing answered
	}
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
	ports := d.def.m.DecoyPorts()
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

// connLogRate caps the socket lookups for the owner of a logged connection
// per second (the nft rule already limits the packets; a flood past this
// still counts, just with the owner "unknown").
const connLogRate = 20

// defenseConnLog reads the NFLOG group of the output chain: the SYN of every
// new outgoing TCP connection, however short it lives. The owning app comes
// from the socket (sock_diag + cgroup) at that moment; "" when the socket is
// already gone or the lookup budget is used up. The poll in defenseConnLoop
// stays as the fallback: while this reader is not running, connLogOK is
// false and the poll feeds the beacon detection itself. Runs until ctx ends.
func (d *Daemon) defenseConnLog(ctx context.Context) {
	var nf *nflog.Nflog
	var err error
	for try := 0; try < 2; try++ {
		nf, err = nflog.Open(&nflog.Config{Group: nft.DefenseConnLogGroup, Copymode: nflog.CopyPacket, Bufsize: 128})
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		d.Log.Warn("defense: no connection log, beacon detection falls back to the 10 s socket poll", "err", err)
		return
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var slot time.Time
	used := 0
	one := func(a nflog.Attribute) {
		if a.Payload == nil || d.def.m == nil || !(d.def.m.Watching(defense.FeatBeacon) || d.def.m.Watching(defense.FeatFirstSeen)) {
			return
		}
		src, dst, ok := defense.ParseConnPacket(*a.Payload)
		if !ok || dst.Port() == 0 {
			return
		}
		if now := time.Now(); now.Sub(slot) >= time.Second {
			slot, used = now, 0
		}
		app := ""
		if used < connLogRate {
			used++
			if o, found := d.sockets.Of("tcp", src); found {
				app = ownerApp(o)
			}
		}
		d.def.m.NoteConn(app, netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()), true)
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		defense.Guard(d.Log, "connection log", func() { one(a) })
		return 0
	}, func(error) int { return 0 })
	if err != nil {
		d.Log.Warn("defense: connection log not readable, beacon detection falls back to the 10 s socket poll", "err", err)
		return
	}
	d.def.connLogOK.Store(true)
	defer d.def.connLogOK.Store(false)
	<-ctx.Done()
}

// defenseNotes lists limits that hold right now (shown in the defense status).
func (d *Daemon) defenseNotes() []string {
	if d.defTableOn() && !d.def.connLogOK.Load() {
		return []string{"beacon detection: connection log not available, using the 10 s socket poll (short connections can be missed)"}
	}
	return nil
}

// connPoll is how often the socket list is read for beacon and first-contact
// detection. Connections shorter than this can be missed, and a beacon
// faster than about twice this interval is not scored reliably.
const connPoll = 10 * time.Second

// defenseConnLoop reads the established and connecting TCP sockets every
// connPoll and hands new outgoing connections (with the owning app, from the
// socket's cgroup) to the defense. Connections whose local port a program
// listens on are inbound and skipped. It only reads while beacon or
// first_seen is on.
func (d *Daemon) defenseConnLoop(ctx context.Context) {
	tk := time.NewTicker(connPoll)
	defer tk.Stop()
	prev := map[string]bool{}
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		if d.def.m == nil || !(d.def.m.Watching(defense.FeatBeacon) || d.def.m.Watching(defense.FeatFirstSeen)) {
			prev, first = map[string]bool{}, true
			continue
		}
		ss, err := sockets.Dump("tcp", 1<<sockets.StateEstablished|1<<synSent)
		if err != nil {
			d.Log.Debug("defense: socket list", "err", err)
			continue
		}
		listen := map[uint16]bool{}
		if l, err := sockets.ListListening(); err == nil {
			for _, s := range l {
				listen[s.Local.Port()] = true
			}
		}
		cur := make(map[string]bool, len(ss))
		for _, s := range ss {
			dst := netip.AddrPortFrom(s.Remote.Addr().Unmap(), s.Remote.Port())
			if !dst.IsValid() || dst.Port() == 0 || listen[s.Local.Port()] {
				continue
			}
			key := fmt.Sprint(s.Inode, "/", s.Local, ">", dst)
			cur[key] = true
			if prev[key] {
				continue
			}
			// with the connection log running, new connections were already
			// reported when they started: the poll then only feeds first
			// contact for what it finds
			d.def.m.NoteConn(d.connApp(s), dst, !first && !d.def.connLogOK.Load())
		}
		prev, first = cur, false
	}
}

// synSent is the kernel's TCP_SYN_SENT state number.
const synSent = 2

// connApp names the program behind a socket: the cgroup's app, or the single
// program of a shared cgroup; "" when that cannot be told.
func (d *Daemon) connApp(s sockets.Socket) string { return ownerApp(d.sockets.Owner(s.Cgroup)) }

func ownerApp(o sockets.Owner) string {
	if !o.Shared {
		return o.Name
	}
	if len(o.Procs) == 1 {
		return o.Procs[0]
	}
	return ""
}

// tlsCheck runs the certificate check once (default route, normal name
// resolution; second way = DoH answer dialled by address). Only one run at a
// time. Quiet when the feature is off or the network is down.
func (d *Daemon) tlsCheck(ctx context.Context) {
	if d.def.m == nil || !d.def.m.Watching(defense.FeatTLS) || !d.def.tlsBusy.CompareAndSwap(false, true) {
		return
	}
	defer d.def.tlsBusy.Store(false)
	st := d.def.m.Status()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tr, ok := d.downloadClient().Transport.(*http.Transport)
		if !ok || tr.DialContext == nil {
			return nil, fmt.Errorf("no dialer")
		}
		return tr.DialContext(ctx, network, addr)
	}
	c := &defense.TLSChecker{M: d.def.m, Path: filepath.Join(d.defenseStateDir(), "tlspins.json")}
	c.Fetch = func(ctx context.Context, host string) ([]*x509.Certificate, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return defense.FetchChain(ctx, dial, net.JoinHostPort(host, "443"), host)
	}
	c.FetchAlt = func(ctx context.Context, host string) ([]*x509.Certificate, error) {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		ips, err := d.dnsReference(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("no second way")
		}
		return defense.FetchChain(ctx, dial, net.JoinHostPort(ips[0].String(), "443"), host)
	}
	c.Run(ctx, defense.TLSTargets(st.Config), st.Class)
}

// defenseTLSLoop checks 20 s after start and then every defense.TLSInterval;
// tlsSoon (a new network) triggers an extra run after a short wait for the link.
func (d *Daemon) defenseTLSLoop(ctx context.Context) {
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.def.tlsSoon:
			t.Reset(15 * time.Second)
			continue
		case <-t.C:
		}
		d.tlsCheck(ctx)
		t.Reset(defense.TLSInterval)
	}
}

// outsideHTTP reaches the outside-check server over one address family,
// directly on the physical link (bypass mark): the check must see this
// machine's own public address, not a tunnel exit.
func (d *Daemon) outsideHTTP(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(engine.MarkBypass))
		}); err != nil {
			return err
		}
		return serr
	}}
	return &http.Client{Timeout: defense.OutsideTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}}
}
