package evidence

import "testing"

func TestScrubDetail(t *testing.T) {
	cases := map[string]string{
		"gateway 00:00:5e:00:53:01 changed":       "gateway <mac> changed",
		"mac 00-00-5E-00-53-02 x":                 "mac <mac> x",
		"ssid=Cafe_Guest reconnect":               "ssid=<removed> reconnect",
		"bssid=00:00:5e:00:53:03":                 "bssid=<removed>",
		"list=feodo port 22 ja3=e7d705a3286e19ea": "list=feodo port 22 ja3=e7d705a3286e19ea",
		"held 12s": "held 12s",
	}
	for in, want := range cases {
		if got := ScrubDetail(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
