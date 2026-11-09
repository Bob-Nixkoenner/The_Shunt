package winsplit

import (
	"reflect"
	"testing"
	"time"
	"unicode/utf16"
)

func utf16z(s string) []byte {
	var b []byte
	for _, c := range append(utf16.Encode([]rune(s)), 0) {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func TestQueryName(t *testing.T) {
	// event 3006: name, then type (UInt32), options, server list ...
	data := append(utf16z("M04-123.Shuntlab.TEST."), 1, 0, 0, 0)
	if got := queryName(data); got != "m04-123.shuntlab.test" {
		t.Errorf("got %q", got)
	}
	if got := queryName(utf16z("bücher.example")); got != "bücher.example" {
		t.Errorf("unicode name: %q", got)
	}
	for _, bad := range [][]byte{nil, {0, 0}, utf16z("a b"), utf16z(`c:\x`), utf16z("a\tb"), utf16z("abc")[:6]} {
		if got := queryName(bad); got != "" {
			t.Errorf("%x: got %q", bad, got)
		}
	}
}

func TestAskTable(t *testing.T) {
	var tab askTable
	now := time.Now()
	tab.add("old.test", `c:\lab\labtun.exe`, now.Add(-askKeep-time.Second))
	tab.add("x.test.", `c:\lab\labtun.exe`, now.Add(-3*time.Second))
	tab.add("X.test", `c:\windows\system32\svchost.exe`, now.Add(-2*time.Second))
	tab.add("x.test", `c:\lab\labtun.exe`, now.Add(-time.Second)) // same program again: one entry, newest
	tab.add("nas", `c:\lab\labdir.exe`, now)

	apps, fresh, _ := tab.get("x.test", now, now.Add(-askFresh))
	if want := []string{`c:\lab\labtun.exe`, `c:\windows\system32\svchost.exe`}; !reflect.DeepEqual(apps, want) || !fresh {
		t.Errorf("x.test: %v fresh=%v", apps, fresh)
	}
	if apps, fresh, _ := tab.get("x.test", now, now); len(apps) != 2 || fresh {
		t.Errorf("x.test asked before the query: %v fresh=%v", apps, fresh)
	}
	if apps, _, _ := tab.get("old.test", now, now); len(apps) != 0 {
		t.Errorf("forgotten ask still there: %v", apps)
	}
	// the DNS client sends "nas" with its search suffix
	if apps, fresh, _ := tab.get("NAS.home.arpa.", now, now.Add(-askFresh)); len(apps) != 1 || apps[0] != `c:\lab\labdir.exe` || !fresh {
		t.Errorf("suffixed name: %v %v", apps, fresh)
	}
	if apps, _, _ := tab.get("other.test", now, now); apps != nil {
		t.Errorf("nobody asked: %v", apps)
	}
	// add wakes a waiter
	_, _, ch := tab.get("late.test", now, now)
	tab.add("late.test", `c:\lab\labtun.exe`, now)
	select {
	case <-ch:
	default:
		t.Error("add did not wake the waiter")
	}
}

func TestAskTableBounded(t *testing.T) {
	var tab askTable
	now := time.Now()
	for i := 0; i < askPerName+3; i++ {
		tab.add("many.test", string(rune('a'+i))+".exe", now)
	}
	if apps, _, _ := tab.get("many.test", now, now); len(apps) != askPerName {
		t.Errorf("%d askers kept, want %d", len(apps), askPerName)
	}
	for i := 0; i < askMaxNames+10; i++ {
		tab.add(string(rune(0x4e00+i))+".test", "a.exe", now)
	}
	if len(tab.names) > askMaxNames {
		t.Errorf("%d names kept", len(tab.names))
	}
}
