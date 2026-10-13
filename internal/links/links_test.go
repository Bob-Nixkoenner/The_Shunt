package links

import "testing"

func TestChoose(t *testing.T) {
	s := choose([]candidate{
		{Link{Kind: "ethernet", Name: "enx1"}, 700},
		{Link{Kind: "ethernet", Name: "eno1"}, 100},
		{Link{Kind: "wifi", Name: "wlp60s0"}, 600},
		{Link{Kind: "", Name: "docker0"}, 0},
	})
	if s.Iface("ethernet") != "eno1" || s.Iface("wifi") != "wlp60s0" || s.Iface("mobile") != "" || len(s) != 2 {
		t.Fatalf("%+v", s)
	}
	if s.Names() != "ethernet=eno1;wifi=wlp60s0" {
		t.Error(s.Names())
	}
}
