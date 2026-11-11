package evidence

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestPcapRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewPcapWriter(&buf, "The Shunt test")
	if err != nil {
		t.Fatal(err)
	}
	eth, _ := w.AddInterface(LinkEthernet, 1500, "control")
	raw, _ := w.AddInterface(LinkRaw, 128, "inbound")
	t0 := time.Date(2026, 11, 11, 10, 0, 0, 123456789, time.UTC)
	if err := w.WritePacket(eth, t0, []byte{1, 2, 3, 4, 5}, 5, "event=7"); err != nil {
		t.Fatal(err)
	}
	long := bytes.Repeat([]byte{0xAB}, 300)
	if err := w.WritePacket(raw, t0.Add(time.Second), long, 300, "event=8"); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(raw, t0.Add(2*time.Second), []byte{9}, 1, ""); err != nil {
		t.Fatal(err)
	}
	if buf.Len()%4 != 0 {
		t.Fatalf("file size %d not a multiple of 4", buf.Len())
	}
	// header bytes per spec
	if binary.LittleEndian.Uint32(buf.Bytes()) != 0x0A0D0D0A || binary.LittleEndian.Uint32(buf.Bytes()[8:]) != 0x1A2B3C4D {
		t.Fatal("bad section header")
	}
	ps, err := ReadPcap(bytes.NewReader(buf.Bytes()))
	if err != nil || len(ps) != 3 {
		t.Fatalf("read: %v, %d packets", err, len(ps))
	}
	if ps[0].Comment != "event=7" || ps[0].Link != LinkEthernet || !ps[0].Time.Equal(t0) || !bytes.Equal(ps[0].Data, []byte{1, 2, 3, 4, 5}) || ps[0].IfName != "control" {
		t.Fatalf("packet 0: %+v", ps[0])
	}
	if len(ps[1].Data) != 128 || ps[1].OrigLen != 300 || ps[1].Link != LinkRaw || ps[1].Comment != "event=8" {
		t.Fatalf("packet 1 (cut to snaplen, original length kept): len %d orig %d", len(ps[1].Data), ps[1].OrigLen)
	}
	if ps[2].Comment != "" {
		t.Fatal("comment appeared from nowhere")
	}
	if _, err := w.AddInterface(LinkRaw, 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(9, t0, nil, 0, ""); err == nil {
		t.Fatal("unknown interface accepted")
	}
}

func TestPcapReaderRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, bytes.Repeat([]byte{0xff}, 64), []byte("not a pcapng file at all")} {
		if _, err := ReadPcap(bytes.NewReader(b)); err == nil && len(b) > 0 {
			t.Fatalf("garbage %q accepted", b)
		}
	}
	// truncated real file
	var buf bytes.Buffer
	w, _ := NewPcapWriter(&buf, "x")
	id, _ := w.AddInterface(LinkRaw, 100, "")
	_ = w.WritePacket(id, time.Unix(1, 0), []byte{1, 2, 3}, 3, "c")
	if _, err := ReadPcap(bytes.NewReader(buf.Bytes()[:buf.Len()-6])); err == nil {
		t.Fatal("truncated file accepted")
	}
}

func FuzzReadPcap(f *testing.F) {
	var buf bytes.Buffer
	w, _ := NewPcapWriter(&buf, "x")
	id, _ := w.AddInterface(LinkEthernet, 100, "n")
	_ = w.WritePacket(id, time.Unix(1, 0), []byte{1, 2, 3}, 3, "event=1")
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, _ := ReadPcap(bytes.NewReader(b))
		for _, p := range ps {
			if len(p.Data) > maxBlock {
				t.Fatal("oversized packet")
			}
		}
	})
}
