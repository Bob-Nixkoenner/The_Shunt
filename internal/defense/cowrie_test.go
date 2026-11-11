package defense

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestTelnetIACParsing(t *testing.T) {
	var out bytes.Buffer
	in := "\xff\xfd\x18\xff\xfb\x1f\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0ro\xff\xffot\r\x00" + "pa\x00ss\r\n" + "x\r\ny\n"
	ti := newTelnetIO(strings.NewReader(in), &out)
	l1, ok1 := ti.readLine()
	if !ok1 || l1 != "ro\xffot" {
		t.Fatalf("line1 %q", l1)
	}
	l2, _ := ti.readLine()
	l3, _ := ti.readLine()
	l4, _ := ti.readLine()
	l5, ok := ti.readLine()
	if l2 != "pass" || l3 != "x" || l4 != "y" || ok || l5 != "" {
		t.Fatalf("%q %q %q %q", l2, l3, l4, l5)
	}
	// DO TTYPE -> WONT, WILL NAWS -> DONT
	if got := out.Bytes(); !bytes.Equal(got, []byte{255, 252, 0x18, 255, 254, 0x1f}) {
		t.Fatalf("replies % x", got)
	}
}

func FuzzTelnetParser(f *testing.F) {
	f.Add([]byte("\xff\xfd\x01root\r\n"))
	f.Add([]byte("\xff\xfa\x18\x00\xff\xf0a\r\x00"))
	f.Add([]byte("\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ti := newTelnetIO(bytes.NewReader(b), io.Discard)
		for i := 0; i < len(b)+2; i++ {
			l, ok := ti.readLine()
			if len(l) > maxLine {
				t.Fatal("line too long")
			}
			if !ok {
				return
			}
		}
	})
}

type hitLog struct {
	mu sync.Mutex
	h  []Hit
}

func (l *hitLog) add(h Hit) { l.mu.Lock(); l.h = append(l.h, h); l.mu.Unlock() }
func (l *hitLog) cowrie() []Hit {
	l.mu.Lock()
	defer l.mu.Unlock()
	var r []Hit
	for _, h := range l.h {
		if h.Kind == KindCowrie {
			r = append(r, h)
		}
	}
	return r
}

func TestTelnetTrapNegotiation(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.Start([]int{2323}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	c := pm.dial(t, 2323)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	greet := make([]byte, 6)
	if _, err := io.ReadFull(c, greet); err != nil || !bytes.Equal(greet, []byte{255, 251, 1, 255, 251, 3}) {
		t.Fatalf("greeting % x %v", greet, err)
	}
	// client agrees and sends credentials with IAC bytes mixed in
	c.Write([]byte{255, 253, 1, 255, 253, 3, 255, 251, 24})
	c.Write([]byte("ro\xff\xfd\x20ot\r\x00hunter2secret\r\n"))
	for i := 0; i < 2; i++ {
		c.Write([]byte("admin\r\nabc\r\n"))
	}
	all, _ := io.ReadAll(c) // server hangs up after 3 tries
	s := string(all)
	if strings.Count(s, "Login incorrect") != 3 || !strings.Contains(s, "Password: ") {
		t.Fatalf("%q", s)
	}
	waitFor(t, "3 cowrie events", func() bool { return len(hl.cowrie()) == 3 })
	hs := hl.cowrie()
	if !strings.Contains(hs[0].Detail, "user=root") || !strings.Contains(hs[0].Detail, "len=13") {
		t.Fatalf("%q", hs[0].Detail)
	}
	for _, h := range hs {
		if strings.Contains(h.Detail, "hunter2") || strings.Contains(h.Detail, "\xff") {
			t.Fatal("leak or control byte")
		}
	}
}

func TestSSHDecoy(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.Start([]int{2222}, DecoyOptions{Cowrie: true})
	defer d.Stop()

	for i, pw := range []string{"hunter2secret", "x", "adminadmin"} {
		raw := pm.dial(t, 2222)
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		cc := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(pw)},
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { return nil },
			ClientVersion:   "SSH-2.0-testclient"}
		conn, _, _, err := ssh.NewClientConn(raw, "decoy", cc)
		if err == nil {
			conn.Close()
			t.Fatal("login must fail")
		}
		if i == 0 {
			var se *ssh.ServerAuthError
			if !errors.As(err, &se) && !strings.Contains(err.Error(), "unable to authenticate") {
				t.Fatalf("err %v", err)
			}
		}
		raw.Close()
	}
	waitFor(t, "3 ssh events", func() bool { return len(hl.cowrie()) == 3 })
	hs := hl.cowrie()
	if !strings.Contains(hs[0].Detail, "user=root") || !strings.Contains(hs[0].Detail, "len=13") || !strings.Contains(hs[0].Detail, "testclient") {
		t.Fatalf("%q", hs[0].Detail)
	}
	for _, h := range hs {
		if strings.Contains(h.Detail, "hunter2") {
			t.Fatal("password stored")
		}
	}
}

func TestSSHDecoyBannerAndKeyboardInteractive(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.SSHBanner = "SSH-2.0-TestBanner_1"
	d.Start([]int{22}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	raw := pm.dial(t, 22)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	var got string
	cc := &ssh.ClientConfig{User: "pi",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			return []string{"secretpw"}, nil
		})},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { got = k.Type(); return nil }}
	if _, _, _, err := ssh.NewClientConn(raw, "decoy", cc); err == nil {
		t.Fatal("login must fail")
	}
	if got != "ssh-ed25519" {
		t.Fatalf("host key %q", got)
	}
	waitFor(t, "kbd event", func() bool { return len(hl.cowrie()) >= 1 })
	if h := hl.cowrie()[0]; !strings.Contains(h.Detail, "user=pi") || !strings.Contains(h.Detail, "len=8") || strings.Contains(h.Detail, "secretpw") {
		t.Fatalf("%q", h.Detail)
	}
}

func TestHostKeyPersisted(t *testing.T) {
	p := t.TempDir() + "/sub/hostkey"
	a, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateHostKey(p)
	if err != nil || !bytes.Equal(a.PublicKey().Marshal(), b.PublicKey().Marshal()) {
		t.Fatal("key not stable", err)
	}
	if fi, _ := statMode(p); fi != 0o600 {
		t.Fatalf("mode %o", fi)
	}
}

func statMode(p string) (uint32, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return uint32(fi.Mode().Perm()), nil
}
