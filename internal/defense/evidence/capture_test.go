package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCapturePreRollInRAMUntilTrigger(t *testing.T) {
	clk := &clock{time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "evidence", "pcap")
	c := &Capture{Dir: dir, PreCount: 4, Now: clk.now, Window: 30 * time.Second}
	for i := 0; i < 10; i++ {
		clk.t = clk.t.Add(time.Second)
		c.Packet(IfInbound, bytes.Repeat([]byte{byte(i)}, 300), 300)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("something was written to disk before any event")
	}
	if c.Buffered() != 4 {
		t.Fatalf("pre-roll holds %d packets", c.Buffered())
	}
	if err := c.Trigger(42); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(5 * time.Second)
	c.Packet(IfControl, []byte{1, 2, 3}, 3) // inside the window
	clk.t = clk.t.Add(40 * time.Second)     // window over
	c.Packet(IfControl, []byte{9, 9, 9}, 3) // goes to the ring, not the file
	c.Tick()
	files := PcapFiles(dir)
	if len(files) != 1 {
		t.Fatalf("files %v", files)
	}
	fi, _ := os.Stat(filepath.Join(dir, files[0]))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	b, _ := os.ReadFile(filepath.Join(dir, files[0]))
	ps, err := ReadPcap(bytes.NewReader(b))
	if err != nil || len(ps) != 5 {
		t.Fatalf("read back: %v, %d packets", err, len(ps))
	}
	for _, p := range ps {
		if p.Comment != "event=42" {
			t.Fatalf("comment %q", p.Comment)
		}
	}
	if len(ps[0].Data) != SnapInbound || ps[0].OrigLen != 300 || ps[0].Link != LinkRaw {
		t.Fatalf("inbound payload not cut to %d: %d", SnapInbound, len(ps[0].Data))
	}
	if ps[4].Link != LinkEthernet || len(ps[4].Data) != 3 {
		t.Fatal("control frame lost")
	}
	if c.Buffered() != 1 {
		t.Fatalf("late packet should wait in the ring, ring=%d", c.Buffered())
	}
}

func TestCaptureSecondEventExtendsAndRelabels(t *testing.T) {
	clk := &clock{time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "p")
	c := &Capture{Dir: dir, Now: clk.now, Window: 30 * time.Second}
	c.Packet(IfInbound, []byte{1}, 1)
	_ = c.Trigger(1)
	clk.t = clk.t.Add(20 * time.Second)
	_ = c.Trigger(2)
	clk.t = clk.t.Add(20 * time.Second) // 40 s after the first, 20 s after the second
	c.Packet(IfInbound, []byte{2}, 1)
	c.Close()
	files := PcapFiles(dir)
	if len(files) != 1 {
		t.Fatalf("%v", files)
	}
	b, _ := os.ReadFile(filepath.Join(dir, files[0]))
	ps, _ := ReadPcap(bytes.NewReader(b))
	if len(ps) != 2 || ps[0].Comment != "event=1" || ps[1].Comment != "event=2" {
		t.Fatalf("%+v", ps)
	}
}

func TestCaptureSizeLimitAndPinned(t *testing.T) {
	clk := &clock{time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "p")
	pin := func(first, last uint64) bool { return first == 1 }
	c := &Capture{Dir: dir, Now: clk.now, Window: time.Second, MaxBytes: 4000, Protect: pin}
	for seq := uint64(1); seq <= 6; seq++ {
		clk.t = clk.t.Add(time.Minute)
		for i := 0; i < 3; i++ {
			c.Packet(IfControl, bytes.Repeat([]byte{1}, 400), 400)
		}
		if err := c.Trigger(seq); err != nil {
			t.Fatal(err)
		}
		clk.t = clk.t.Add(5 * time.Second)
		c.Tick()
	}
	names := PcapFiles(dir)
	if dirSize(dir) > 4000+2000 {
		t.Fatalf("limit ignored: %d bytes in %v", dirSize(dir), names)
	}
	has1 := false
	for _, n := range names {
		if pcapName.FindStringSubmatch(n)[1] == "1" {
			has1 = true
		}
	}
	if !has1 {
		t.Fatalf("pinned capture deleted: %v", names)
	}
	if len(names) < 2 {
		t.Fatalf("old captures were not kept at all: %v", names)
	}
}

func TestCaptureRefusesSymlinkDir(t *testing.T) {
	base := t.TempDir()
	_ = os.Mkdir(filepath.Join(base, "real"), 0o700)
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "pcap")); err != nil {
		t.Skip(err)
	}
	c := &Capture{Dir: filepath.Join(base, "pcap")}
	c.Packet(IfControl, []byte{1}, 1)
	if err := c.Trigger(1); err == nil {
		t.Fatal("symlinked capture dir accepted")
	}
}
