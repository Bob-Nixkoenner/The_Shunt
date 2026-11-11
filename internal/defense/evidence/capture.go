package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Capture interfaces (the id inside every capture file).
const (
	IfControl = 0 // Ethernet frames: ARP, DHCP, IPv6 RA/ND
	IfInbound = 1 // raw IP packets: first packets of unsolicited inbound connections
)

// Snap lengths. Payload of unsolicited inbound traffic is cut hard.
const (
	SnapInbound = 128
	SnapControl = 1500
)

// Defaults of the in-memory pre-roll and the post-event window.
const (
	DefaultPreCount = 512
	DefaultPreBytes = 2 << 20
	DefaultWindow   = 60 * time.Second
	maxCaptureFile  = 16 << 20
)

type ramPacket struct {
	at   time.Time
	ifID int
	data []byte
	orig int
}

// Capture keeps a small ring of recent packets in memory only. Nothing
// reaches the disk until an event of severity Medium or above calls
// Trigger: then the ring (pre-roll) and the next Window of packets are
// written to a pcapng file (0600). Which packets may be fed in is the
// caller's job (see the Linux sources); this type never captures anything
// itself.
type Capture struct {
	Dir      string // evidence/pcap
	MaxBytes int64  // total size limit of the directory (0 = 100 MiB)
	PreCount int
	PreBytes int
	Window   time.Duration
	Now      func() time.Time
	// Protect exempts captures of pinned cases from the size limit.
	Protect Protect

	mu       sync.Mutex
	ring     []ramPacket
	ringSize int
	f        *os.File
	pw       *PcapWriter
	until    time.Time
	seq      uint64
	fname    string
}

func (c *Capture) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Capture) limits() (int, int, time.Duration, int64) {
	pc, pb, w, mb := c.PreCount, c.PreBytes, c.Window, c.MaxBytes
	if pc <= 0 {
		pc = DefaultPreCount
	}
	if pb <= 0 {
		pb = DefaultPreBytes
	}
	if w <= 0 {
		w = DefaultWindow
	}
	if mb <= 0 {
		mb = 100 << 20
	}
	return pc, pb, w, mb
}

// Packet hands one packet to the capture. ifID is IfControl or IfInbound.
func (c *Capture) Packet(ifID int, data []byte, orig int) {
	snap := SnapControl
	if ifID == IfInbound {
		snap = SnapInbound
	}
	if len(data) > snap {
		data = data[:snap]
	}
	cp := append([]byte(nil), data...)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tickLocked(now)
	if c.pw != nil {
		c.writeLocked(ramPacket{now, ifID, cp, orig}, c.seq)
		return
	}
	pc, pb, _, _ := c.limits()
	c.ring = append(c.ring, ramPacket{now, ifID, cp, orig})
	c.ringSize += len(cp)
	for len(c.ring) > pc || c.ringSize > pb {
		c.ringSize -= len(c.ring[0].data)
		c.ring = c.ring[1:]
	}
}

func (c *Capture) writeLocked(p ramPacket, seq uint64) {
	if c.pw == nil {
		return
	}
	if c.pw.Written() > maxCaptureFile {
		c.closeLocked()
		return
	}
	_ = c.pw.WritePacket(p.ifID, p.at, p.data, p.orig, "event="+strconv.FormatUint(seq, 10))
}

// Trigger is called for an event worth keeping (log line seq, severity
// Medium or above): flush the pre-roll to a new file and keep writing for
// Window. A second trigger inside the window extends it and re-labels the
// following packets.
func (c *Capture) Trigger(seq uint64) error {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tickLocked(now)
	_, _, win, mb := c.limits()
	if c.pw == nil {
		if err := SafeDir(c.Dir); err != nil {
			return err
		}
		PrunePcap(c.Dir, mb-mb/10, c.Protect) // make room before a new file
		name := fmt.Sprintf("%s-%d.pcapng", now.UTC().Format("20060102T150405Z"), seq)
		f, err := os.OpenFile(filepath.Join(c.Dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
		if err != nil {
			return err
		}
		pw, err := NewPcapWriter(f, "The Shunt evidence capture")
		if err == nil {
			_, err = pw.AddInterface(LinkEthernet, SnapControl, "control frames")
		}
		if err == nil {
			_, err = pw.AddInterface(LinkRaw, SnapInbound, "unsolicited inbound")
		}
		if err != nil {
			f.Close()
			return err
		}
		c.f, c.pw, c.fname = f, pw, name
		for _, p := range c.ring {
			c.writeLocked(p, seq)
		}
		c.ring, c.ringSize = nil, 0
	}
	c.seq = seq
	c.until = now.Add(win)
	return nil
}

// Tick closes the file when the window is over (call it every few seconds).
func (c *Capture) Tick() {
	c.mu.Lock()
	c.tickLocked(c.now())
	c.mu.Unlock()
}

func (c *Capture) tickLocked(now time.Time) {
	if c.pw != nil && now.After(c.until) {
		c.closeLocked()
	}
}

func (c *Capture) closeLocked() {
	if c.f != nil {
		_ = c.f.Sync()
		_ = c.f.Close()
	}
	c.f, c.pw = nil, nil
}

// Close ends the current file; the ring is dropped.
func (c *Capture) Close() {
	c.mu.Lock()
	c.closeLocked()
	c.ring, c.ringSize = nil, 0
	c.mu.Unlock()
}

// Buffered is the number of packets in the memory ring (tests, status).
func (c *Capture) Buffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ring)
}

var pcapName = regexp.MustCompile(`^\d{8}T\d{6}Z-(\d+)\.pcapng$`)

// PrunePcap deletes the oldest captures until the directory is at most max
// bytes, except captures that belong to a pinned case (by the seq in the
// file name). The newest file is kept even if it alone is over the limit.
func PrunePcap(dir string, max int64, protect Protect) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	var total int64
	for _, d := range des {
		if d.Type().IsRegular() && pcapName.MatchString(d.Name()) {
			names = append(names, d.Name())
			total += fileSize(filepath.Join(dir, d.Name()))
		}
	}
	sort.Strings(names)
	for i, n := range names {
		if total <= max {
			return
		}
		if max > 1 && i == len(names)-1 {
			return
		}
		if protect != nil {
			if m := pcapName.FindStringSubmatch(n); m != nil {
				if s, err := strconv.ParseUint(m[1], 10, 64); err == nil && protect(s, s) {
					continue
				}
			}
		}
		sz := fileSize(filepath.Join(dir, n))
		if os.Remove(filepath.Join(dir, n)) == nil {
			total -= sz
		}
	}
}

// PcapFiles lists the capture files of dir (names only), oldest first.
func PcapFiles(dir string) []string {
	des, _ := os.ReadDir(dir)
	var out []string
	for _, d := range des {
		if d.Type().IsRegular() && pcapName.MatchString(d.Name()) && !strings.Contains(d.Name(), "/") {
			out = append(out, d.Name())
		}
	}
	sort.Strings(out)
	return out
}
