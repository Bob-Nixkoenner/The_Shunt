package probe

import "testing"

func TestJudge(t *testing.T) {
	rs := []RouteResult{
		{Route: "direct", Result: Result{IP: "1.1.1.1", Resolver: "9.9.9.9"}},
		{Route: "block"},
		{Route: "tunnel:good", Result: Result{IP: "2.2.2.2", Resolver: "8.8.8.8"}},
		{Route: "tunnel:leaky", Result: Result{IP: "1.1.1.1", Resolver: "8.8.8.8"}},
		{Route: "tunnel:dnsleak", Result: Result{IP: "2.2.2.2", Resolver: "9.9.9.9"}},
		{Route: "tunnel:down", Result: Result{IPErr: "x", DNSErr: "y"}},
		{Route: "tunnel:err", Verdict: "error"},
		{Route: "link:ethernet", Result: Result{IP: "1.1.1.1", Resolver: "9.9.9.9"}},
		{Route: "link:wifi"},
	}
	judge(rs)
	want := []string{"ok", "blocked", "ok", "leak", "warn", "blocked", "error", "ok", "blocked"}
	for i, w := range want {
		if rs[i].Verdict != w {
			t.Errorf("%s: got %s want %s", rs[i].Route, rs[i].Verdict, w)
		}
	}
}
