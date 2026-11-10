package winsplit

import (
	"bytes"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

type fakeVals struct{ m map[string]RegVal }

func (f *fakeVals) Get(k, n string) (RegVal, bool, error) { v, ok := f.m[k+"|"+n]; return v, ok, nil }
func (f *fakeVals) Set(k, n string, v RegVal) error       { f.m[k+"|"+n] = v; return nil }
func (f *fakeVals) Delete(k, n string) error              { delete(f.m, k+"|"+n); return nil }
func (f *fakeVals) SubKeys(k string) ([]string, error) {
	seen := map[string]bool{}
	for key := range f.m {
		p := strings.SplitN(key, "|", 2)[0]
		if strings.HasPrefix(p, k+`\`) {
			seen[strings.SplitN(strings.TrimPrefix(p, k+`\`), `\`, 2)[0]] = true
		}
	}
	var r []string
	for s := range seen {
		r = append(r, s)
	}
	sort.Strings(r)
	return r, nil
}

const (
	gEth  = "{80523D8A-F771-467C-8F05-322C5BE1E301}"
	gShnt = "{77EC8A3F-231C-4F57-BC34-F4AC98CA248C}"
	gWifi = "{11111111-2222-3333-4444-555555555555}"
)

func newFake() *fakeVals {
	f := &fakeVals{m: map[string]RegVal{}}
	nic := func(sub, guid, dev, conn string, iftype uint32) {
		k := nicKey(sub)
		f.m[k+"|NetCfgInstanceId"] = RegVal{Kind: "sz", S: guid}
		f.m[k+"|DeviceInstanceID"] = RegVal{Kind: "sz", S: dev}
		f.m[k+"|*IfType"] = RegVal{Kind: "dword", D: iftype}
		f.m[netConnKey+`\`+guid+`\Connection|Name`] = RegVal{Kind: "sz", S: conn}
		f.m[ifaceKey(guid)+"|RegistrationEnabled"] = RegVal{Kind: "dword", D: 1}
	}
	nic("0001", gEth, `PCI\VEN_8086&DEV_100E\3&267a`, "Ethernet", 6)
	nic("0002", gShnt, `SWD\Wintun\`+gShnt, "Shunt", 53)
	nic("0003", gWifi, `PCI\VEN_8086&DEV_2723\4&1`, "WLAN", 71)
	f.m[tcpipParams+"|Hostname"] = RegVal{Kind: "sz", S: "my-pc"}
	f.m[tcpipParams+"|NV Hostname"] = RegVal{Kind: "sz", S: "my-pc"}
	f.m[tcpip6Params+"|Dhcpv6DUID"] = RegVal{Kind: "bin", B: []byte{0, 1, 0, 1, 9, 9, 9, 9, 8, 0, 39, 1, 2, 3}}
	return f
}

func newTarn(t *testing.T, f *fakeVals, restarts *[]string) *Tarn {
	tr := NewTarn(f, filepath.Join(t.TempDir(), "t.json"), func(c string) error { *restarts = append(*restarts, c); return nil })
	tr.Rand = rand.New(rand.NewSource(7))
	return tr
}

func TestNeutralValues(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	n := NeutralHostname(r)
	if len(n) != 15 || !strings.HasPrefix(n, "DESKTOP-") {
		t.Errorf("name %q", n)
	}
	for i := 0; i < 200; i++ {
		m := RandomMAC(r)
		if !ValidMAC(m) {
			t.Fatalf("mac %q", m)
		}
	}
	if ValidMAC("0100276E1111") || ValidMAC("08002700AAAA") || ValidMAC("0A00") {
		t.Error("ValidMAC accepts multicast / universal / short")
	}
	a, b := StableMAC("s1", gEth), StableMAC("s1", strings.ToLower(gEth))
	if a != b || !ValidMAC(a) || a == StableMAC("s2", gEth) || a == StableMAC("s1", gWifi) {
		t.Errorf("stable %s %s", a, b)
	}
	d := NeutralDUID("0A00276E1111")
	if !bytes.Equal(d, []byte{0, 3, 0, 1, 0x0A, 0, 0x27, 0x6E, 0x11, 0x11}) {
		t.Errorf("duid %v", d)
	}
}

func TestListNICsAndEligibility(t *testing.T) {
	var got []string
	for _, n := range ListNICs(newFake()) {
		got = append(got, n.Sub+":"+n.Conn+":"+map[bool]string{true: "cable", false: "-"}[n.Cable()]+":"+map[bool]string{true: "reg", false: "-"}[n.Registers()])
	}
	want := "0001:Ethernet:cable:reg 0002:Shunt:-:- 0003:WLAN:-:reg"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v", got)
	}
}

func TestWantFor(t *testing.T) {
	c := &config.Config{Daemon: config.Daemon{DHCPHostname: "none", MAC: "random"},
		Networks: []config.Network{{Name: "home", DHCPHostname: "send", MAC: "permanent"}, {Name: "x"}}}
	if w := WantFor(c, ""); !w.HideName || w.MAC != "random" {
		t.Errorf("%+v", w)
	}
	if w := WantFor(c, "home"); w.HideName || w.MAC != "permanent" {
		t.Errorf("%+v", w)
	}
	if w := WantFor(c, "x"); !w.HideName || w.MAC != "random" {
		t.Errorf("%+v", w)
	}
	if w := WantFor(nil, ""); w.HideName || w.MAC != "" {
		t.Errorf("%+v", w)
	}
}

func TestApplyRandomKeepsAndRestores(t *testing.T) {
	f, var1 := newFake(), []string{}
	tr := newTarn(t, f, &var1)
	if _, err := tr.Apply(Want{HideName: true, MAC: "random"}); err != nil {
		t.Fatal(err)
	}
	mac := f.m[nicKey("0001")+"|NetworkAddress"].S
	if !ValidMAC(mac) || len(var1) != 1 || var1[0] != "Ethernet" {
		t.Fatalf("mac %q restarts %v", mac, var1)
	}
	for _, g := range []string{gEth, gWifi} {
		if f.m[ifaceKey(g)+"|RegistrationEnabled"].D != 0 {
			t.Errorf("registration %s still on", g)
		}
	}
	if _, ok := f.m[nicKey("0002")+"|NetworkAddress"]; ok {
		t.Error("tunnel adapter touched")
	}
	if _, ok := f.m[nicKey("0003")+"|NetworkAddress"]; ok {
		t.Error("Wi-Fi adapter touched")
	}
	// again: same value, no second restart
	if _, err := tr.Apply(Want{HideName: true, MAC: "random"}); err != nil || len(var1) != 1 || f.m[nicKey("0001")+"|NetworkAddress"].S != mac {
		t.Errorf("not idempotent: %v %v", err, var1)
	}
	// trusted network: everything back, MAC value gone again
	if _, err := tr.Apply(Want{HideName: false, MAC: "permanent"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.m[nicKey("0001")+"|NetworkAddress"]; ok || len(var1) != 2 {
		t.Errorf("MAC not restored: %v", var1)
	}
	if f.m[ifaceKey(gEth)+"|RegistrationEnabled"].D != 1 {
		t.Error("registration not restored")
	}
}

func TestApplyKeepsUserOwnAddress(t *testing.T) {
	f, rs := newFake(), []string{}
	f.m[nicKey("0001")+"|NetworkAddress"] = RegVal{Kind: "sz", S: "0200000000AA"}
	tr := newTarn(t, f, &rs)
	_, _ = tr.Apply(Want{MAC: "stable"})
	if got := f.m[nicKey("0001")+"|NetworkAddress"].S; got == "0200000000AA" || !ValidMAC(got) {
		t.Fatalf("stable not set: %s", got)
	}
	_, _ = tr.Apply(Want{MAC: ""})
	if got := f.m[nicKey("0001")+"|NetworkAddress"].S; got != "0200000000AA" {
		t.Errorf("user's own address lost: %s", got)
	}
}

func TestStableIsStable(t *testing.T) {
	f, rs := newFake(), []string{}
	tr := newTarn(t, f, &rs)
	_, _ = tr.Apply(Want{MAC: "stable"})
	a := f.m[nicKey("0001")+"|NetworkAddress"].S
	_, _ = tr.Apply(Want{MAC: "permanent"})
	_, _ = tr.Apply(Want{MAC: "stable"})
	if b := f.m[nicKey("0001")+"|NetworkAddress"].S; a != b {
		t.Errorf("stable changed: %s %s", a, b)
	}
}

func TestShutdownBootCycle(t *testing.T) {
	f, rs := newFake(), []string{}
	tr := newTarn(t, f, &rs)
	orig6 := f.m[tcpip6Params+"|Dhcpv6DUID"]
	if err := tr.PrepareShutdown(Want{HideName: true, MAC: "random"}); err != nil {
		t.Fatal(err)
	}
	h := f.m[tcpipParams+"|Hostname"].S
	if !strings.HasPrefix(h, "DESKTOP-") || f.m[tcpipParams+"|NV Hostname"].S != h {
		t.Fatalf("hostname %q", h)
	}
	mac := f.m[nicKey("0001")+"|NetworkAddress"].S
	duid := f.m[tcpip6Params+"|Dhcpv6DUID"].B
	if !ValidMAC(mac) || len(duid) != 10 || duid[1] != 3 {
		t.Fatalf("mac %q duid %v", mac, duid)
	}
	// "reboot": a new process (new Tarn on the same file) starts
	tr2 := NewTarn(f, tr.File, func(c string) error { rs = append(rs, c); return nil })
	if err := tr2.RestoreBoot(); err != nil {
		t.Fatal(err)
	}
	if f.m[tcpipParams+"|Hostname"].S != "my-pc" || f.m[tcpipParams+"|NV Hostname"].S != "my-pc" || !f.m[tcpip6Params+"|Dhcpv6DUID"].equal(orig6) {
		t.Errorf("boot values not restored: %v", f.m)
	}
	// the MAC chosen for this boot stays and is adopted without restart
	if _, err := tr2.Apply(Want{HideName: true, MAC: "random"}); err != nil || f.m[nicKey("0001")+"|NetworkAddress"].S != mac || len(rs) != 0 {
		t.Errorf("mac not adopted: %v %v", err, rs)
	}
}

func TestRestoreBootAfterSomeoneRenamed(t *testing.T) {
	f, rs := newFake(), []string{}
	tr := newTarn(t, f, &rs)
	_ = tr.PrepareShutdown(Want{HideName: true})
	f.m[tcpipParams+"|Hostname"] = RegVal{Kind: "sz", S: "renamed-by-user"}
	_ = tr.RestoreBoot()
	if f.m[tcpipParams+"|Hostname"].S != "renamed-by-user" {
		t.Error("a name changed by someone else was overwritten")
	}
}

func TestRestoreAllUninstall(t *testing.T) {
	f, rs := newFake(), []string{}
	before := map[string]RegVal{}
	for k, v := range f.m {
		before[k] = v
	}
	tr := newTarn(t, f, &rs)
	_, _ = tr.Apply(Want{HideName: true, MAC: "random"})
	_ = tr.PrepareShutdown(Want{HideName: true, MAC: "random"})
	if err := tr.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	if len(f.m) != len(before) {
		t.Errorf("registry differs: %d vs %d", len(f.m), len(before))
	}
	for k, v := range before {
		if !f.m[k].equal(v) {
			t.Errorf("%s: %v vs %v", k, f.m[k], v)
		}
	}
}
