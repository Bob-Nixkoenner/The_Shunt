package winsplit

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type fakeReg struct{ m map[string]uint32 }

func (f *fakeReg) GetDWORD(k, n string) (uint32, bool, error) {
	v, ok := f.m[k+"|"+n]
	return v, ok, nil
}
func (f *fakeReg) SetDWORD(k, n string, v uint32) error { f.m[k+"|"+n] = v; return nil }
func (f *fakeReg) DeleteValue(k, n string) error        { delete(f.m, k+"|"+n); return nil }
func (f *fakeReg) SubKeys(k string) ([]string, error) {
	seen := map[string]bool{}
	for key := range f.m {
		p := strings.SplitN(key, "|", 2)[0]
		if strings.HasPrefix(p, k+`\`) {
			seen[strings.TrimPrefix(p, k+`\`)] = true
		}
	}
	var r []string
	for s := range seen {
		r = append(r, s)
	}
	sort.Strings(r)
	return r, nil
}

const ifA = netbtIfacesKey + `\Tcpip_{A}`
const ifB = netbtIfacesKey + `\Tcpip_{B}`

func newTest(t *testing.T, m map[string]uint32) (*quietReg, *fakeReg) {
	f := &fakeReg{m: m}
	return newQuietReg(f, filepath.Join(t.TempDir(), "q.json")), f
}

func exists(f *fakeReg, k, n string) bool { _, ok := f.m[k+"|"+n]; return ok }

func TestQuietRegRoundTrip(t *testing.T) {
	q, f := newTest(t, map[string]uint32{ifA + "|NetbiosOptions": 0, dnsClientPolicyKey + "|EnableMDNS": 1})
	if err := q.apply(); err != nil {
		t.Fatal(err)
	}
	if f.m[ifA+"|NetbiosOptions"] != 2 || !exists(f, dnsClientPolicyKey, "EnableMulticast") || f.m[dnsClientPolicyKey+"|EnableMulticast"] != 0 || f.m[dnsClientPolicyKey+"|EnableMDNS"] != 0 {
		t.Fatalf("not set: %v", f.m)
	}
	n := len(q.load())
	_ = q.apply() // idempotent
	if len(q.load()) != n {
		t.Fatal("apply not idempotent")
	}
	f.m[ifB+"|NetbiosOptions"] = 1 // adapter appearing later
	_ = q.apply()
	if f.m[ifB+"|NetbiosOptions"] != 2 {
		t.Fatal("new adapter missed")
	}
	if err := q.restore(); err != nil {
		t.Fatal(err)
	}
	if f.m[ifA+"|NetbiosOptions"] != 0 || f.m[ifB+"|NetbiosOptions"] != 1 || f.m[dnsClientPolicyKey+"|EnableMDNS"] != 1 {
		t.Fatalf("not restored: %v", f.m)
	}
	if exists(f, dnsClientPolicyKey, "EnableMulticast") {
		t.Fatal("absent value not deleted")
	}
	if len(q.load()) != 0 {
		t.Fatal("state left")
	}
}

func TestQuietRegKeepsUserPolicy(t *testing.T) {
	q, f := newTest(t, map[string]uint32{
		dnsClientPolicyKey + "|EnableMulticast": 0,
		ifA + "|NetbiosOptions":                 2,
	})
	_ = q.apply()
	_ = q.restore()
	if v, ok := f.m[dnsClientPolicyKey+"|EnableMulticast"]; !ok || v != 0 {
		t.Fatal("user policy lost")
	}
	if f.m[ifA+"|NetbiosOptions"] != 2 {
		t.Fatal("user NetbiosOptions lost")
	}
}

func TestQuietRegChangedMeanwhile(t *testing.T) {
	q, f := newTest(t, map[string]uint32{ifA + "|NetbiosOptions": 0})
	_ = q.apply()
	f.m[ifA+"|NetbiosOptions"] = 1 // user changed it
	_ = q.restore()
	if f.m[ifA+"|NetbiosOptions"] != 1 {
		t.Fatal("overwrote later user change")
	}
}

// NCSI boot hold: set at shutdown, taken back at the next start; a policy the
// administrator set is neither changed nor taken back.
func TestNCSIBootHold(t *testing.T) {
	st := &fakeReg{m: map[string]uint32{}}
	g := newRegGuard(st, filepath.Join(t.TempDir(), "ncsi.json"), ncsiValues())
	if err := g.apply(); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := st.GetDWORD(ncsiPolicyKey, "NoActiveProbe"); !ok || v != 1 {
		t.Fatal("hold not set")
	}
	if err := g.restore(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetDWORD(ncsiPolicyKey, "NoActiveProbe"); ok {
		t.Fatal("hold not taken back (the value did not exist before)")
	}
	// the administrator's own policy stays
	_ = st.SetDWORD(ncsiPolicyKey, "NoActiveProbe", 1)
	g2 := newRegGuard(st, filepath.Join(t.TempDir(), "ncsi.json"), ncsiValues())
	_ = g2.apply()
	_ = g2.restore()
	if v, ok, _ := st.GetDWORD(ncsiPolicyKey, "NoActiveProbe"); !ok || v != 1 {
		t.Fatal("a policy we did not set must stay")
	}
	// restore without an earlier apply (watchdog at start) changes nothing
	g3 := newRegGuard(st, filepath.Join(t.TempDir(), "ncsi.json"), ncsiValues())
	if err := g3.restore(); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := st.GetDWORD(ncsiPolicyKey, "NoActiveProbe"); v != 1 {
		t.Fatal("watchdog touched a foreign value")
	}
}

func TestOnlyNCSIServices(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want bool
	}{
		{[]string{"netprofm", "NlaSvc"}, true},
		{[]string{"NlaSvc"}, true},
		{[]string{"NLASVC", "NetProfM"}, true},
		{nil, false},
		{[]string{"NlaSvc", "Dnscache"}, false},
		{[]string{"Dnscache"}, false},
	} {
		if got := onlyNCSIServices(c.in); got != c.want {
			t.Errorf("onlyNCSIServices(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTunnelsReady(t *testing.T) {
	for _, c := range []struct {
		name, js string
		want     bool
	}{
		{"no tunnels", `{"tunnels":[]}`, true},
		{"up with handshake", `{"tunnels":[{"type":"wireguard","up":true,"handshake":1793000000}]}`, true},
		{"up without handshake", `{"tunnels":[{"type":"wireguard","up":true,"handshake":0}]}`, false},
		{"one of two waits", `{"tunnels":[{"type":"wireguard","up":true,"handshake":5},{"type":"wireguard","up":true,"handshake":0}]}`, false},
		{"down tunnel does not hold it back", `{"tunnels":[{"type":"wireguard","up":false,"handshake":0}]}`, true},
		{"tor has no handshake", `{"tunnels":[{"type":"tor","up":true,"handshake":0}]}`, true},
		{"garbage", `nope`, false},
	} {
		if got := TunnelsReady(c.js); got != c.want {
			t.Errorf("%s: TunnelsReady = %v, want %v", c.name, got, c.want)
		}
	}
}
