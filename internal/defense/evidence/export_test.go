package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exportFixture(t *testing.T) (*Log, string, *clock, Case) {
	clk := &clock{time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, clk, nil)
	l.SetNetClass("public")
	srcs := []string{"192.0.2.7", "198.51.100.4", "192.0.2.7", "2001:db8::5", "192.0.2.7"}
	for _, s := range srcs {
		clk.t = clk.t.Add(time.Second)
		_, _ = l.Append(Input{Kind: "decoy_hit", Severity: "medium", Src: s, Port: 22, Proto: "tcp", Detail: "hit"})
	}
	cs := Case{ID: "c1", Name: "test case", Src: "192.0.2.7", FromSeq: 1, Pinned: true}
	return l, dir, clk, cs
}

func TestExportAndVerifyArchive(t *testing.T) {
	l, dir, clk, cs := exportFixture(t)
	// a capture labelled with events of the case and one of another source
	pc := &Capture{Dir: filepath.Join(dir, PcapDir), Now: clk.now, Window: time.Second}
	raw := func(src [4]byte) []byte {
		p := make([]byte, 40)
		p[0] = 0x45
		copy(p[12:], src[:])
		return p
	}
	pc.Packet(IfInbound, raw([4]byte{192, 0, 2, 7}), 40)
	pc.Packet(IfInbound, raw([4]byte{198, 51, 100, 4}), 40) // other source: must stay out
	pc.Packet(IfControl, []byte{1, 2, 3, 4}, 4)
	_ = pc.Trigger(1)
	pc.Close()
	l.Close()

	out := filepath.Join(t.TempDir(), "out")
	res, err := Export(context.Background(), ExportOptions{Dir: dir, Case: &cs, OutDir: out, Version: "v-test", ClockSynced: func() (bool, bool) { return true, true }, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if res.Lines != 3 || res.Addresses != 1 || res.Packets != 2 {
		t.Fatalf("%+v", res)
	}
	if fi, _ := os.Stat(res.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o700 {
		t.Fatalf("out dir mode %v", fi.Mode())
	}
	rep, err := VerifyPath(res.Path)
	if err != nil || !rep.OK || rep.Lines != 3 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	// look inside
	b, _ := os.ReadFile(res.Path)
	files, err := readArchive(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{FileEvents, FileChain, FileCapture, FileManifest, FileReadme, FileAddrTXT, FileAddrCSV} {
		if len(files[n]) == 0 {
			t.Errorf("%s missing", n)
		}
	}
	if string(files[FileAddrTXT]) != "192.0.2.7\n" {
		t.Fatalf("addresses.txt %q", files[FileAddrTXT])
	}
	if !strings.Contains(string(files[FileAddrCSV]), "192.0.2.7,3,") {
		t.Fatalf("csv %q", files[FileAddrCSV])
	}
	if strings.Contains(string(files[FileEvents]), "198.51.100.4") {
		t.Fatal("other source's lines in the export")
	}
	// the chain proof carries the hashes of lines in between, not their content
	if strings.Count(string(files[FileChain]), "\n") != 5 || strings.Contains(string(files[FileChain]), "198.51") {
		t.Fatalf("chain.jsonl %q", files[FileChain])
	}
	ps, _ := ReadPcap(bytes.NewReader(files[FileCapture]))
	if len(ps) != 2 {
		t.Fatalf("capture has %d packets, want the case's inbound packet and the control frame", len(ps))
	}
	man := string(files[FileManifest])
	for _, bad := range []string{"hostname", "/home/"} {
		if strings.Contains(man, bad) {
			t.Fatal("manifest leaks " + bad)
		}
	}
	if !strings.Contains(man, "NTP synchronised at export: yes") || !strings.Contains(man, "go1") {
		t.Fatalf("manifest %s", man)
	}
	if !strings.Contains(string(files[FileReadme]), "not legal advice") {
		t.Fatal("legal note missing")
	}
	// a clean export has no state lines of other cases
}

func TestVerifyArchiveDetectsChanges(t *testing.T) {
	l, dir, clk, cs := exportFixture(t)
	l.Close()
	res, err := Export(context.Background(), ExportOptions{Dir: dir, Case: &cs, OutDir: t.TempDir(), Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(res.Path)
	files, _ := readArchive(bytes.NewReader(b))
	mut := map[string]func(m map[string][]byte){
		"edited event": func(m map[string][]byte) {
			m[FileEvents] = bytes.Replace(m[FileEvents], []byte("192.0.2.7"), []byte("192.0.2.8"), 1)
		},
		"dropped line": func(m map[string][]byte) {
			i := bytes.IndexByte(m[FileEvents], '\n')
			m[FileEvents] = m[FileEvents][i+1:]
		},
		"edited chain": func(m map[string][]byte) {
			m[FileChain] = bytes.Replace(m[FileChain], []byte(`"seq":2`), []byte(`"seq":9`), 1)
		},
		"edited readme": func(m map[string][]byte) { m[FileReadme] = append(m[FileReadme], 'x') },
		"missing file":  func(m map[string][]byte) { delete(m, FileAddrCSV) },
		"extra file":    func(m map[string][]byte) { m[FileAddrTXT+""] = []byte("x"); m[FileCapture] = []byte("x") },
	}
	for name, f := range mut {
		c := map[string][]byte{}
		for k, v := range files {
			c[k] = append([]byte(nil), v...)
		}
		f(c)
		if r := VerifyArchiveFiles(c); r.OK {
			t.Errorf("%s: not detected", name)
		}
	}
	if r := VerifyArchiveFiles(files); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestReadArchiveRefusesTraversalAndOddMembers(t *testing.T) {
	mk := func(h tar.Header, body string) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		h.Size = int64(len(body))
		_ = tw.WriteHeader(&h)
		_, _ = tw.Write([]byte(body))
		tw.Close()
		gz.Close()
		return buf.Bytes()
	}
	for name, a := range map[string][]byte{
		"dotdot":   mk(tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Mode: 0o600}, "x"),
		"absolute": mk(tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o600}, "x"),
		"subdir":   mk(tar.Header{Name: "a/events.jsonl", Typeflag: tar.TypeReg, Mode: 0o600}, "x"),
		"symlink":  mk(tar.Header{Name: FileEvents, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, ""),
		"unknown":  mk(tar.Header{Name: "run.sh", Typeflag: tar.TypeReg, Mode: 0o700}, "x"),
	} {
		if _, err := readArchive(bytes.NewReader(a)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := readArchive(strings.NewReader("junk")); err == nil {
		t.Error("junk accepted")
	}
}

func TestExportErrorsAndSrcMode(t *testing.T) {
	l, dir, clk, _ := exportFixture(t)
	l.Close()
	if _, err := Export(context.Background(), ExportOptions{Dir: dir}); err == nil {
		t.Fatal("no case or src accepted")
	}
	if _, err := Export(context.Background(), ExportOptions{Dir: dir, Src: "not-an-ip"}); err == nil {
		t.Fatal("bad src accepted")
	}
	if _, err := Export(context.Background(), ExportOptions{Dir: dir, Src: "203.0.113.1", OutDir: t.TempDir()}); err == nil {
		t.Fatal("empty case accepted")
	}
	res, err := Export(context.Background(), ExportOptions{Dir: dir, Src: "2001:db8::5", OutDir: t.TempDir(), Now: clk.now})
	if err != nil || res.Lines != 1 || strings.Contains(filepath.Base(res.Path), ":") {
		t.Fatalf("%+v %v", res, err)
	}
	if r, _ := VerifyPath(res.Path); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestTimestampRequestAndExport(t *testing.T) {
	var d [32]byte
	for i := range d {
		d[i] = byte(i)
	}
	req := timestampRequest(d, [8]byte{0xff, 1, 2, 3, 4, 5, 6, 7})
	if hex.EncodeToString(req[:3]) != "304302" || len(req) != 69 || req[len(req)-3] != 0x01 {
		t.Fatalf("request %x", req)
	}
	if !bytes.Contains(req, d[:]) || req[58] != 0x7f {
		t.Fatalf("layout %x", req)
	}
	granted := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00}
	if !timestampGranted(granted) || timestampGranted([]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02}) || timestampGranted([]byte("x")) {
		t.Fatal("status parsing")
	}
	var got []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Error("content type")
		}
		w.Write(granted)
	}))
	defer srv.Close()
	l, dir, clk, cs := exportFixture(t)
	l.Close()
	res, err := Export(context.Background(), ExportOptions{Dir: dir, Case: &cs, OutDir: t.TempDir(), Now: clk.now, TSA: srv.URL, TSAClient: srv.Client()})
	if err != nil || !res.Timestamped || len(got) != 69 {
		t.Fatalf("%+v %v", res, err)
	}
	if r, _ := VerifyPath(res.Path); !r.OK || len(r.Notes) == 0 {
		t.Fatalf("%+v", r)
	}
	// plain http is refused, the export still works without
	res, err = Export(context.Background(), ExportOptions{Dir: dir, Case: &cs, OutDir: t.TempDir(), Now: clk.now, TSA: "http://tsa.example.net/"})
	if err != nil || res.Timestamped || res.Note == "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestVerifyPathLiveDir(t *testing.T) {
	l, dir, _, _ := exportFixture(t)
	l.Close()
	if r, err := VerifyPath(dir); err != nil || !r.OK || r.Lines != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := VerifyPath(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing path accepted")
	}
}
