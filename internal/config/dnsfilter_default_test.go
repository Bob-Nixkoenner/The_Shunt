package config

import "testing"

func TestDefaultFilterPerOS(t *testing.T) {
	has := func(l []string, n string) bool {
		for _, x := range l {
			if x == n {
				return true
			}
		}
		return false
	}
	win := defaultDNSFilterFor("windows")
	if !has(win.Lists(FilterNormal), "Win10Telemetry") || !has(win.Lists(FilterNormal), "MS-Office-Telemetry") {
		t.Error("Windows: telemetry lists belong in normal")
	}
	for _, os := range []string{"linux", "android", "darwin"} {
		f := defaultDNSFilterFor(os)
		for _, n := range []string{"Win10Telemetry", "MS-Office-Telemetry"} {
			if has(f.Lists(FilterParanoid), n) {
				t.Errorf("%s: %s must not be in any default", os, n)
			}
		}
	}
	for _, os := range []string{"windows", "linux"} {
		f := defaultDNSFilterFor(os)
		for _, n := range []string{"samsung", "lg-tv"} {
			if has(f.Lists(FilterParanoid), n) {
				t.Errorf("%s: phone/TV list %s in the defaults", os, n)
			}
		}
	}
}

func TestListDuplicates(t *testing.T) {
	f := DNSFilter{
		Low:      []string{"easylist", "malware"},
		Normal:   []string{DefaultFilterSource + "easylist", "notserious", "notserious"},
		Paranoid: []string{"malware", "crypto"},
	}
	if got := f.Lists(FilterParanoid); len(got) != 4 { // easylist, malware, notserious, crypto
		t.Errorf("lists %v", got)
	}
	d := f.Duplicates()
	if len(d) != 3 {
		t.Errorf("duplicates %v", d)
	}
	if got := DefaultDNSFilter().Duplicates(); len(got) != 0 {
		t.Errorf("defaults have duplicates: %v", got)
	}
}

func TestTidy(t *testing.T) {
	f := DNSFilter{Low: []string{"easylist"}, Normal: []string{DefaultFilterSource + "easylist", "malware"}, Paranoid: []string{"malware", "crypto"}}.Tidy()
	if len(f.Low) != 1 || len(f.Normal) != 1 || f.Normal[0] != "malware" || len(f.Paranoid) != 1 || f.Paranoid[0] != "crypto" {
		t.Errorf("tidy %+v", f)
	}
	if len(f.Duplicates()) != 0 {
		t.Error("still duplicates")
	}
}

func TestLocalListRef(t *testing.T) {
	if validListRef("x", "file:relative.txt") == nil || validListRef("x", "file:/a/../b") == nil {
		t.Error("relative or .. path accepted")
	}
	if validListRef("x", "file:/etc/lists/mine.txt") != nil {
		t.Error("absolute path rejected")
	}
}

// The HaGeZi tiers build on each other: one of Light, Pro, Pro++ per level,
// and every default reference must be valid.
func TestHageziDefaults(t *testing.T) {
	f := DefaultDNSFilter()
	for _, lvl := range FilterLevels {
		for _, l := range f.Lists(lvl) {
			if err := validListRef("test", l); err != nil {
				t.Errorf("%s: %v", lvl, err)
			}
		}
	}
	for _, bad := range []string{"hagezi:", "hagezi:../x", "hagezi:Pro", "hagezi:a/b", "hagezi:-x"} {
		if validListRef("test", bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"hagezi:pro", "hagezi:pro.plus", "hagezi:tif.mini", "hagezi:native.winoffice"} {
		if err := validListRef("test", good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}
