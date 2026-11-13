package defense

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBaitCredsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "bait.json")
	a, err := LoadOrCreateBait(p)
	if err != nil || !a.valid() {
		t.Fatalf("%+v %v", a, err)
	}
	if m, _ := statMode(p); m&0o777 != 0o600 {
		t.Fatalf("mode %o", m)
	}
	b, err := LoadOrCreateBait(p)
	if err != nil || b != a {
		t.Fatalf("not kept: %+v %+v %v", a, b, err)
	}
	if !a.Match(a.Password) || !a.Match(a.Token) || a.Match(a.User) || a.Match("") || a.Match(a.Password+"x") {
		t.Fatal("match")
	}
	if (BaitCreds{}).Match("") {
		t.Fatal("empty creds must match nothing")
	}
	c, _ := NewBaitCreds()
	if c.Password == a.Password || c.Token == a.Token {
		t.Fatal("not random")
	}
	// damaged: moved aside and replaced
	os.WriteFile(p, []byte("{"), 0o600)
	d, err := LoadOrCreateBait(p)
	if err != nil || d == a || !d.valid() {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := os.Stat(p + ".bad"); err != nil {
		t.Fatal("not moved aside")
	}
	// a link is refused
	l := filepath.Join(dir, "link.json")
	os.Symlink(p, l)
	if _, err := LoadOrCreateBait(l); err == nil {
		t.Fatal("symlink accepted")
	}
	// memory only
	if m, err := LoadOrCreateBait(""); err != nil || !m.valid() {
		t.Fatal(err)
	}
}

func decoyURL(pm *portMap, port int, p string) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return fmt.Sprintf("http://127.0.0.1:%d%s", pm.real[port], p)
}

func (l *hitLog) kind(k Kind) []Hit {
	l.mu.Lock()
	defer l.mu.Unlock()
	var r []Hit
	for _, h := range l.h {
		if h.Kind == k {
			r = append(r, h)
		}
	}
	return r
}

func httpGet(t *testing.T, u string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHTTPDecoyBaitFilesAndLogin(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.BaitPath = filepath.Join(t.TempDir(), "bait.json")
	d.Start([]int{80, 23, 2222}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	b, ok := d.bait()
	if !ok {
		t.Fatal("no bait")
	}

	code, body := httpGet(t, decoyURL(pm, 80, "/"), nil)
	if code != 200 || !strings.Contains(body, `name="password"`) {
		t.Fatalf("%d %q", code, body)
	}
	for p, want := range map[string]string{"/.env": "DB_PASSWORD=" + b.Password, "/.git/config": b.User + ":" + b.Password + "@",
		"/config.php.bak": "$api_token = '" + b.Token} {
		code, body := httpGet(t, decoyURL(pm, 80, p), nil)
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("%s: %d %q", p, code, body)
		}
	}
	if code, _ := httpGet(t, decoyURL(pm, 80, "/nothing/here"), nil); code != 404 {
		t.Fatal(code)
	}
	// wrong login: a normal fake-login event without the password
	resp, err := http.PostForm(decoyURL(pm, 80, "/login"), url.Values{"username": {"admin"}, "password": {"hunter2secret"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, "http login", func() bool {
		for _, h := range hl.cowrie() {
			if strings.HasPrefix(h.Detail, "http login user=admin len=13") {
				return true
			}
		}
		return false
	})
	if len(hl.kind(KindBait)) != 0 {
		t.Fatal("wrong password counted as bait")
	}
	served := 0
	for _, h := range hl.cowrie() {
		if strings.Contains(h.Detail, "hunter2") || strings.Contains(h.Detail, b.Password) {
			t.Fatalf("secret in detail %q", h.Detail)
		}
		if strings.Contains(h.Detail, "bait=served") {
			served++
		}
	}
	if served != 3 {
		t.Fatalf("served %d", served)
	}

	// the bait password at the HTTP form, as token in a header, at telnet and ssh
	resp, err = http.PostForm(decoyURL(pm, 80, "/login"), url.Values{"username": {b.User}, "password": {b.Password}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	httpGet(t, decoyURL(pm, 80, "/api"), map[string]string{"Authorization": "Bearer " + b.Token})

	c := pm.dial(t, 23)
	r := bufio.NewReader(c)
	c.Write([]byte("root\r\n" + b.Password + "\r\n"))
	r.ReadString('P')
	c.Close()

	raw := pm.dial(t, 2222)
	cc := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(b.Password)},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil }}
	if conn, _, _, err := ssh.NewClientConn(raw, "decoy", cc); err == nil {
		conn.Close()
		t.Fatal("login must fail")
	}
	raw.Close()

	waitFor(t, "4 bait events", func() bool { return len(hl.kind(KindBait)) == 4 })
	vias := map[string]bool{}
	for _, h := range hl.kind(KindBait) {
		if h.Sev != SevHigh || strings.Contains(h.Detail, b.Password) || strings.Contains(h.Detail, b.Token) {
			t.Fatalf("%+v", h)
		}
		for _, v := range []string{"http", "telnet", "ssh"} {
			if strings.Contains(h.Detail, "via="+v+" ") {
				vias[v] = true
			}
		}
	}
	if len(vias) != 3 {
		t.Fatalf("vias %v", vias)
	}
}

func TestHTTPDecoyLimits(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.Start([]int{8080}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	// keep-alive: at most httpMaxRequests answers, then the decoy hangs up
	c := pm.dial(t, 8080)
	defer c.Close()
	for i := 0; i < httpMaxRequests+3; i++ {
		fmt.Fprintf(c, "GET /x%d HTTP/1.1\r\nHost: a\r\n\r\n", i)
	}
	all, _ := io.ReadAll(c)
	if n := strings.Count(string(all), "HTTP/1.1 404"); n != httpMaxRequests {
		t.Fatalf("answers %d", n)
	}
	// an oversized form body ends the connection, garbage ends it at once
	c2 := pm.dial(t, 8080)
	defer c2.Close()
	big := strings.Repeat("a", httpMaxBody*2)
	fmt.Fprintf(c2, "POST /login HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(big), big)
	all, _ = io.ReadAll(c2)
	if !strings.Contains(string(all), "Connection: close") {
		t.Fatalf("%q", all)
	}
	c3 := pm.dial(t, 8080)
	defer c3.Close()
	c3.Write([]byte("\x16\x03\x01garbage\r\n\r\n"))
	if all, _ := io.ReadAll(c3); len(all) != 0 {
		t.Fatalf("%q", all)
	}
}

func TestFormCreds(t *testing.T) {
	if u, p, ok := formCreds("application/json", []byte(`{"email":"a@b","passwd":"x"}`)); !ok || u != "a@b" || p != "x" {
		t.Fatal(u, p, ok)
	}
	if u, p, ok := formCreds("", []byte("login=r&pwd=y")); !ok || u != "r" || p != "y" {
		t.Fatal(u, p, ok)
	}
	if _, _, ok := formCreds("", []byte("q=1")); ok {
		t.Fatal("no password field")
	}
}

func TestManagerBaitUseBans(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 4)
	m, _ := newTestManager(t, pm, banCh)
	m.dec.SSHDelay = 0
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = []int{23}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnknown)
	b, _ := m.dec.bait()
	useBait := func() {
		c := pm.dial(t, 23)
		c.Write([]byte("root\r\n" + b.Password + "\r\n"))
		bufio.NewReader(c).ReadString('P')
		c.Close()
	}
	// block switch off: reported (high), not blocked
	useBait()
	waitFor(t, "bait event", func() bool { return m.Status().Counts[KindBait] == 1 })
	if len(m.Status().Bans) != 0 {
		t.Fatal("banned with block off")
	}
	if h := m.Status().Heat; h < 40 {
		t.Fatalf("heat %d", h)
	}
	// block on: at once, reason bait
	cfg.Features[FeatBrute] = Feature{Watch: true, Block: true}
	m.Configure(cfg)
	useBait()
	select {
	case ban := <-banCh:
		if ban.Reason != KindBait || ban.Src != "127.0.0.1" {
			t.Fatalf("%+v", ban)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ban")
	}
	m.Unban("")
	// an ignored device: nothing at all
	cfg.Ignore = []IgnoreEntry{{Addr: "127.0.0.0/8"}}
	m.Configure(cfg)
	n := m.Status().Counts[KindBait]
	useBait()
	time.Sleep(200 * time.Millisecond)
	if m.Status().Counts[KindBait] != n || len(m.Status().Bans) != 0 {
		t.Fatal("ignored device reported or blocked")
	}
}

// What a visitor sends cannot add fields to the event detail: a user name or
// path with " tool=nmap" must not become a tool mark (extra heat).
func TestVisitorFieldsCannotAddDetailFields(t *testing.T) {
	for _, s := range []string{"root tool=nmap", "/a tool=nmap", "x via=bait"} {
		got := cleanField(s)
		if strings.Contains(got, " ") || hasTool(" user="+got) {
			t.Fatalf("cleanField(%q) = %q", s, got)
		}
	}
}
