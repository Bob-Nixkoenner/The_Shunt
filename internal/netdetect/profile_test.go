package netdetect

import "testing"

func TestPickProfile(t *testing.T) {
	two := []ProfileConn{{"Ethernet", CatPrivate}, {"WLAN", CatPublic}}
	if got := PickProfile(two, "wlan"); got != "public" {
		t.Fatal(got)
	}
	if got := PickProfile(two, "Other"); got != "" {
		t.Fatal("several, no match:", got)
	}
	if got := PickProfile(two[:1], "Other"); got != "private" {
		t.Fatal("single:", got)
	}
	if got := PickProfile([]ProfileConn{{"x", CatDomain}}, ""); got != "domain" {
		t.Fatal(got)
	}
	if got := PickProfile(nil, "x"); got != "" {
		t.Fatal(got)
	}
	if ProfileName(9) != "" {
		t.Fatal("unknown category")
	}
}

func TestClassHint(t *testing.T) {
	for p, want := range map[string]string{"public": "unsafe", "private": "unknown", "domain": "unknown", "": "unknown"} {
		if got := ClassHint(p); got != want {
			t.Errorf("ClassHint(%q)=%q want %q", p, got, want)
		}
	}
}
