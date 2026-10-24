package doh

import "testing"

func TestUnwanted(t *testing.T) {
	for name, want := range map[string][2]bool{ // {blockDoH off, on}
		"use-application-dns.net": {true, true},
		"dns.google":              {false, true},
		"x.cloudflare-dns.com":    {false, true},
		"example.com":             {false, false},
		"notdns.google.example":   {false, false},
	} {
		if Unwanted(name, false) != want[0] || Unwanted(name, true) != want[1] {
			t.Errorf("%s", name)
		}
	}
}
