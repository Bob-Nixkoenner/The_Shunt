package defense

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestToolFromUA(t *testing.T) {
	for ua, want := range map[string]string{
		"curl/8.5.0":                "curl",
		"Wget/1.21.4":               "wget",
		"python-requests/2.31.0":    "python_requests",
		"Python-urllib/3.12":        "python_urllib",
		"python-httpx/0.27.0":       "python_httpx",
		"Python/3.12 aiohttp/3.9.5": "python_aiohttp",
		"Go-http-client/1.1":        "go_http",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)":                               "nmap",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36": "headless_chromium",
		"Mozilla/5.0 HeadlessChrome/130.0 Playwright/1.48":                                                              "playwright",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0":                       "",
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0":                                        "",
		"": "",
	} {
		if got := ToolFromUA(ua); got != want {
			t.Errorf("%q: %q want %q", ua, got, want)
		}
	}
	if toolFromRequest("/nice%20ports%2C/Tri%6Eity.txt%2ebak", "") != "nmap" {
		t.Error("nmap 404 probe")
	}
}

func TestToolFromSSHAndPayload(t *testing.T) {
	for v, want := range map[string]string{
		"SSH-2.0-Nmap-SSH2-Hostkey":  "nmap",
		"SSH-2.0-paramiko_3.4.0":     "python_paramiko",
		"SSH-2.0-AsyncSSH_2.14.2":    "python_asyncssh",
		"SSH-2.0-libssh_0.10.6":      "libssh",
		"SSH-2.0-Go":                 "go_ssh",
		"SSH-2.0-OpenSSH_9.6p1":      "",
		"SSH-2.0-PuTTY_Release_0.81": "",
	} {
		if got := ToolFromSSHClient(v); got != want {
			t.Errorf("%q: %q want %q", v, got, want)
		}
	}
	for p, want := range map[string]string{
		"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\n":             "nmap",
		"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n":                "nmap",
		"GET / HTTP/1.0\r\nUser-Agent: python-requests/2.31\r\n\r\n":               "python_requests",
		"GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: Mozilla/5.0 Firefox/132\r\n\r\n": "",
		"\r\n\r\n":     "", // nmap's GenericLines, but sent by many tools
		"\x16\x03\x01": "",
	} {
		if got := toolFromPayload([]byte(p)); got != want {
			t.Errorf("%q: %q want %q", p, got, want)
		}
	}
}

func TestToolMarksOnDecoys(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.Start([]int{80, 21}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	httpGet(t, decoyURL(pm, 80, "/.env"), map[string]string{"User-Agent": "curl/8.5.0"})
	httpGet(t, decoyURL(pm, 80, "/"), map[string]string{"User-Agent": "Mozilla/5.0 Firefox/132.0"})
	c := pm.dial(t, 21)
	io.ReadAll(io.LimitReader(c, 22)) // FTP banner
	fmt.Fprint(c, "GET / HTTP/1.0\r\nUser-Agent: python-requests/2.31\r\n\r\n")
	io.ReadAll(c)
	c.Close()
	waitFor(t, "probe hit", func() bool {
		for _, h := range hl.kind(KindDecoyHit) {
			if h.Detail == "probe tool=python_requests" && h.Extra && h.Port == 21 {
				return true
			}
		}
		return false
	})
	var curl, plain bool
	for _, h := range hl.cowrie() {
		switch {
		case strings.Contains(h.Detail, "path=/.env") && strings.HasSuffix(h.Detail, " tool=curl"):
			curl = true
		case strings.Contains(h.Detail, "path=/") && !hasTool(h.Detail):
			plain = true
		}
	}
	if !curl || !plain {
		t.Fatalf("%+v", hl.cowrie())
	}
}

func TestThermoToolBonus(t *testing.T) {
	a, b := NewThermo(), NewThermo()
	clk := newClock()
	a.now, b.now = clk.Now, clk.Now
	for i := 0; i < 3; i++ {
		a.Add(Event{Kind: KindCowrie, Severity: SevLow, Detail: "http GET path=/"})
		b.Add(Event{Kind: KindCowrie, Severity: SevLow, Detail: "http GET path=/ tool=curl"})
	}
	if b.Heat() <= a.Heat()+10 {
		t.Fatalf("tool %d plain %d", b.Heat(), a.Heat())
	}
	c := NewThermo()
	c.Add(Event{Kind: KindBan, Severity: SevLow, Detail: "tool=curl"})
	if c.Heat() != 0 {
		t.Fatal("bonus on a zero-point event")
	}
}

// A tool mark alone never blocks, even with every block switch on.
func TestToolMarkNeverBansAlone(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	banCh := make(chan Ban, 4)
	m, _ := newTestManager(t, pm, banCh)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DecoyPorts = []int{80}
	for _, f := range []string{FeatScan, FeatBrute, FeatReputation} {
		cfg.Features[f] = Feature{Watch: true, Block: true}
	}
	m.Configure(cfg)
	m.SetNetwork("k", ClassUnsafe)
	c := pm.dial(t, 80)
	for i := 0; i < httpMaxRequests; i++ {
		fmt.Fprintf(c, "GET /p%d HTTP/1.1\r\nHost: a\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n\r\n", i)
	}
	io.ReadAll(c)
	c.Close()
	waitFor(t, "events", func() bool { return m.Status().Counts[KindCowrie] == httpMaxRequests })
	select {
	case b := <-banCh:
		t.Fatalf("banned on a tool mark: %+v", b)
	case <-time.After(300 * time.Millisecond):
	}
	st := m.Status()
	if st.Counts[KindDecoyHit] != 1 || st.Counts[KindScan] != 0 || st.Counts[KindBruteForce] != 0 || st.Heat < 50 {
		t.Fatalf("%+v heat %d", st.Counts, st.Heat)
	}
}

func TestToolMarkSSH(t *testing.T) {
	pm := &portMap{real: map[int]int{}}
	var hl hitLog
	d := NewDecoys(pm.listen, hl.add)
	d.Start([]int{2222}, DecoyOptions{Cowrie: true})
	defer d.Stop()
	raw := pm.dial(t, 2222)
	cc := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}, ClientVersion: "SSH-2.0-paramiko_3.4.0",
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil }}
	if conn, _, _, err := ssh.NewClientConn(raw, "decoy", cc); err == nil {
		conn.Close()
	}
	raw.Close()
	waitFor(t, "ssh event", func() bool { return len(hl.cowrie()) == 1 })
	if h := hl.cowrie()[0]; !strings.HasPrefix(h.Detail, "ssh login user=root ") || !strings.HasSuffix(h.Detail, " tool=python_paramiko") {
		t.Fatalf("%q", h.Detail)
	}
}
