package daemon

import "testing"

func TestStripResolve(t *testing.T) {
	for in, want := range map[string]string{
		"hosts:          files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns myhostname": "hosts: files mdns4_minimal [NOTFOUND=return] dns myhostname",
		"hosts: files resolve myhostname": "hosts: files myhostname dns",
	} {
		got, changed := StripResolve("passwd: files\n" + in + "\n")
		if !changed || got != "passwd: files\n"+want+"\n" {
			t.Errorf("got %q", got)
		}
	}
	if _, changed := StripResolve("hosts: files dns\n"); changed {
		t.Error("changed a config without resolve")
	}
}
