package ui

import "testing"

func TestUIState(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AppData", t.TempDir())
	v := "1"
	st, err := mergeUIState(map[string]*string{"shunt-fold:main:Apps": &v, "evil": &v})
	if err != nil || st["shunt-fold:main:Apps"] != "1" || st["evil"] != "" {
		t.Fatalf("%v %v", st, err)
	}
	if got := loadUIState(); got["shunt-fold:main:Apps"] != "1" {
		t.Fatalf("not saved: %v", got)
	}
	st, _ = mergeUIState(map[string]*string{"shunt-fold:main:Apps": nil})
	if len(st) != 0 || len(loadUIState()) != 0 {
		t.Fatalf("not removed: %v", st)
	}
}
