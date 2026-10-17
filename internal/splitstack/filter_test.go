package splitstack

import (
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
)

func TestSetFilterBlocksAndRecords(t *testing.T) {
	l, err := blocklist.Parse("ads", strings.NewReader("ads.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	if got := e.blockedName("firefox.exe", "ads.example.com."); got != "" {
		t.Fatalf("no filter set, blocked by %q", got)
	}
	e.SetFilter(blocklist.NewFilter(map[string][]*blocklist.List{"normal": {l}}, nil), "normal")
	if got := e.blockedName("firefox.exe", "Ads.Example.com."); got != "ads" {
		t.Fatalf("blocked by %q, want ads", got)
	}
	if got := e.blockedName("firefox.exe", "fine.example.com."); got != "" {
		t.Fatalf("fine.example.com blocked by %q", got)
	}
	if len(e.recent) != 1 || e.recent[0].Name != "ads.example.com" || e.recent[0].List != "ads" || e.recent[0].Level != "normal" {
		t.Fatalf("recent: %+v", e.recent)
	}
	e.SetFilter(nil, "")
	if got := e.blockedName("firefox.exe", "ads.example.com."); got != "" {
		t.Fatalf("filter removed, blocked by %q", got)
	}
}
