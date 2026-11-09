package dhcphost

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestAppliedOf(t *testing.T) {
	v := dbus.MakeVariant
	// a new cable profile as GetAppliedConnection gives it (defaults left out)
	cable := map[string]map[string]dbus.Variant{
		"connection": {"type": v("802-3-ethernet"), "uuid": v("u1"), "id": v("Netz A")},
		"ipv4":       {"method": v("auto")},
		"ipv6":       {"method": v("auto"), "dhcp-send-hostname-v2": v(int32(-1))},
	}
	a, ok := appliedOf(cable)
	if !ok || a.Wifi || a.UUID != "u1" || !a.Send4 || !a.Send6 {
		t.Errorf("cable: %+v %v", a, ok)
	}
	// set by shuntd: both off
	cable["ipv4"]["dhcp-send-hostname"] = v(false)
	cable["ipv6"]["dhcp-send-hostname-v2"] = v(int32(0))
	if a, _ := appliedOf(cable); a.Send4 || a.Send6 {
		t.Errorf("switched off: %+v", a)
	}
	// Wi-Fi with its name; IPv6 ignored does not ask DHCPv6
	wifi := map[string]map[string]dbus.Variant{
		"connection":      {"type": v("802-11-wireless"), "uuid": v("u2")},
		"802-11-wireless": {"ssid": v([]byte("Cafe"))},
		"ipv4":            {},
		"ipv6":            {"method": v("ignore")},
	}
	if a, ok := appliedOf(wifi); !ok || !a.Wifi || a.SSID != "Cafe" || !a.Send4 || a.Send6 {
		t.Errorf("wifi: %+v %v", a, ok)
	}
	// a WireGuard device: not ours
	wg := map[string]map[string]dbus.Variant{"connection": {"type": v("wireguard"), "uuid": v("u3")}}
	if _, ok := appliedOf(wg); ok {
		t.Error("wireguard must be skipped")
	}
}

func TestGuardOnce(t *testing.T) {
	t0 := time.Now()
	if !guardOnce("g1", t0) {
		t.Fatal("first time must pass")
	}
	if guardOnce("g1", t0.Add(time.Second)) {
		t.Error("restarted twice in a row (loop)")
	}
	if !guardOnce("g2", t0.Add(time.Second)) {
		t.Error("another profile must pass")
	}
	if !guardOnce("g1", t0.Add(guardAgain+time.Second)) {
		t.Error("must pass again after guardAgain")
	}
}

func TestDropUntyped(t *testing.T) {
	v := dbus.MakeVariant
	// an empty a(ayuay) as godbus reads it: untyped, Update2 refuses "aav"
	s := map[string]map[string]dbus.Variant{
		"ipv6": {"addresses": v([]interface{}{}), "routes": v([][]interface{}{}), "method": v("auto"), "address-data": v([]map[string]dbus.Variant{}), "dns": v([][]byte{})},
		"ipv4": {"addresses": v([][]uint32{})},
	}
	dropUntyped(s)
	if _, ok := s["ipv6"]["addresses"]; ok {
		t.Error("ipv6 addresses kept")
	}
	if _, ok := s["ipv6"]["routes"]; ok {
		t.Error("ipv6 routes kept")
	}
	for _, k := range []string{"method", "address-data", "dns"} {
		if _, ok := s["ipv6"][k]; !ok {
			t.Errorf("ipv6 %s dropped", k)
		}
	}
	if _, ok := s["ipv4"]["addresses"]; !ok {
		t.Error("typed ipv4 addresses dropped")
	}
}
