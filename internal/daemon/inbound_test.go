package daemon

import (
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestAppendNetwork(t *testing.T) {
	raw := []byte("[daemon]\ndefault_route = \"direct\"\n[inbound]\nenabled = true\nallow = [\"tcp/1716\"]\n[[network]]\nname = \"cafe-5g\"\nssid = [\"x\"]\ndefault_route = \"direct\"")
	c, err := config.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	name := profileName("Cafe_5G", "AA:BB:CC:DD:EE:FF", c)
	if name != "cafe-5g-2" {
		t.Errorf("name %q", name)
	}
	if n := profileName("", "AA:BB:CC:DD:EE:FF", c); n != "lan-aabbccddeeff" {
		t.Errorf("name without ssid %q", n)
	}
	out := appendNetwork(raw, name, `Wei"fi_5G`, "AA:BB:CC:DD:EE:FF", c.Daemon.DefaultRoute)
	c2, err := config.Parse(string(out))
	if err != nil {
		t.Fatalf("appended config invalid: %v\n%s", err, out)
	}
	n := c2.MatchNetwork(`Wei"fi_5G`, "aa:bb:cc:dd:ee:ff")
	if n == nil || n.Name != name || n.DefaultRoute != "direct" {
		t.Fatalf("profile not matched: %+v", n)
	}
	if mode, allow := c2.InboundFor(name); mode != config.InboundLAN || len(allow) != 1 || allow[0].From != 1716 {
		t.Errorf("inbound %q %v", mode, allow)
	}
	if mode, _ := c2.InboundFor(""); mode != config.InboundClosed {
		t.Errorf("unknown network: %q", mode)
	}
}
