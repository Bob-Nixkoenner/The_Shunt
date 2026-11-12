package defense

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCutSource(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.77":          "192.0.2.0/24",
		"::ffff:198.51.100.9": "198.51.100.0/24",
		"2001:db8:1:2::5":     "2001:db8:1::/48",
		"nope":                "",
		"":                    "",
	} {
		if got := CutSource(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestReportsFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "reports.json")
	clk := newClock()
	m := NewManager(nil, WithClock(clk.Now), WithReportFile(path))
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Features[FeatDecoy] = Feature{}
	m.Configure(cfg)
	m.SetNetwork("aaaaaaaaaaaaaaaa", ClassUnknown)
	m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: "192.0.2.77"})
	m.Report(Event{Kind: KindScan, Severity: SevHigh, Src: "192.0.2.78"})
	m.Report(Event{Kind: KindDNSHijack, Severity: SevHigh})
	m.Report(Event{Kind: KindObservation, Severity: SevInfo, Detail: "captive portal: login first"})
	clk.Add(time.Minute)
	m.Report(Event{Kind: KindBruteForce, Severity: SevMedium, Src: "2001:db8:1:2::5"})
	clk.Add(time.Second)
	m.SetNetwork("bbbbbbbbbbbbbbbb", ClassSafe)
	m.Report(Event{Kind: KindFirstSeen, Severity: SevLow, Src: "203.0.113.5"})

	r := m.Reports(false)
	if len(r.Reports) != 2 || r.Current != "bbbbbbbbbbbbbbbb" || r.Reports[0].Key != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("%+v", r)
	}
	a := r.Reports[1]
	if a.Counts[KindScan] != 2 || a.PeakHeat < 50 || a.DNSRedirect != PropYes || a.Captive != PropYes || a.Isolation != PropUnknown ||
		a.Sources["192.0.2.0/24"] != 2 || a.Sources["2001:db8:1::/48"] != 1 || !a.LastSeen.After(a.FirstSeen) {
		t.Fatalf("%+v", a)
	}
	if b := r.Reports[0]; b.DNSRedirect != PropNoneSeen || b.Counts[KindFirstSeen] != 1 {
		t.Fatalf("%+v", b)
	}
	// export: short key, no current marker, no full addresses
	ex := m.Reports(true)
	if !ex.Export || ex.Current != "" || len(ex.Reports[0].Key) != 8 {
		t.Fatalf("%+v", ex)
	}
	m.Close() // flushes
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", st, err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "192.0.2.77") || strings.Contains(string(b), "2001:db8:1:2") {
		t.Fatal("full address stored")
	}
	// reload from file
	if n := len(NewReports(path).List(false).Reports); n != 2 {
		t.Fatalf("reload: %d", n)
	}
	os.WriteFile(path, []byte("{broken"), 0o600)
	if n := len(NewReports(path).List(false).Reports); n != 0 {
		t.Fatal("broken file must give empty reports")
	}
}

func TestReportsDisabledAndCap(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	m.SetNetwork("k", ClassUnknown) // disabled: nothing recorded
	m.Report(Event{Kind: KindScan, Src: "192.0.2.1"})
	if n := len(m.Reports(false).Reports); n != 0 {
		t.Fatalf("disabled: %d", n)
	}
	r := NewReports("")
	now := time.Now()
	for i := 0; i < MaxReports+5; i++ {
		r.Enter("key"+itoa(i), ClassUnknown, now.Add(time.Duration(i)*time.Second), true)
	}
	got := r.List(false).Reports
	if len(got) != MaxReports || got[len(got)-1].Key == "key0" {
		t.Fatalf("cap: %d", len(got))
	}
	// source list is bounded
	for i := 0; i < 200; i++ {
		r.Note(Event{Kind: KindScan, Src: "10.0." + itoa(i) + ".1", Time: now}, 1)
	}
	for _, x := range r.List(false).Reports {
		if x.Key == "key68" && len(x.Sources) != maxReportSources {
			t.Fatalf("sources: %d", len(x.Sources))
		}
	}
}
