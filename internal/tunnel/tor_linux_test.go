package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakePT(t *testing.T, names ...string) {
	d := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(d, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := ptDirs
	ptDirs = []string{d}
	t.Setenv("PATH", d)
	t.Cleanup(func() { ptDirs = old })
}

func TestTorPluginsLyrebird(t *testing.T) {
	fakePT(t, "lyrebird")
	got, err := torPlugins(ExpandBridges([]string{"snowflake", "obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0", "[2001:db8::1]:443 BBBB"}))
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if !strings.HasPrefix(got[0], "ClientTransportPlugin obfs4,snowflake exec ") || !strings.HasSuffix(got[0], "/lyrebird") {
		t.Errorf("line %q", got[0])
	}
}

func TestTorPluginsMissing(t *testing.T) {
	fakePT(t)
	if _, err := torPlugins([]string{"obfs4 1.2.3.4:443 AAAA cert=x"}); err == nil {
		t.Error("obfs4 bridge without a transport program was accepted")
	}
	if got, err := torPlugins([]string{"1.2.3.4:443 AAAA"}); err != nil || got != nil {
		t.Errorf("plain bridge: %v %v", got, err)
	}
}

func TestTorPluginsFallback(t *testing.T) {
	fakePT(t, "obfs4proxy", "snowflake-client")
	got, err := torPlugins([]string{"obfs4 1.2.3.4:443 AAAA cert=x", "snowflake 192.0.2.3:80 BBBB"})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestExpandBridges(t *testing.T) {
	got := ExpandBridges([]string{"snowflake", "obfs4 1.2.3.4:443 AAAA cert=x"})
	if len(got) != len(builtinBridges["snowflake"])+1 || got[len(got)-1] != "obfs4 1.2.3.4:443 AAAA cert=x" {
		t.Errorf("%d lines", len(got))
	}
}

func TestTorrcBridges(t *testing.T) {
	tr := &Tor{spec: TorSpec{Name: "x", DataDir: "/d", Isolate: "app", Bridges: []string{"obfs4 1.2.3.4:443 AAAA cert=x"}}, dir: "/r", dnsPort: 9053}
	rc, err := tr.torrc([]string{"ClientTransportPlugin obfs4 exec /usr/libexec/shunt/lyrebird"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"UseBridges 1", "Bridge obfs4 1.2.3.4:443 AAAA cert=x", "ClientTransportPlugin obfs4 exec /usr/libexec/shunt/lyrebird", "SocksPort unix:/r/socks"} {
		if !strings.Contains(rc, want) {
			t.Errorf("torrc lacks %q", want)
		}
	}
	if strings.Contains(rc, "IsolateDestAddr") {
		t.Error("app isolation must not add flags")
	}
}
