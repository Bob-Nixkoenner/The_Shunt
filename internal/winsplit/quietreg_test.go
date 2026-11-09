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
