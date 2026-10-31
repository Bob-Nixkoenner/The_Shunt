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

func TestLevelMigration(t *testing.T) {
	for in, want := range map[string]string{"normal": "simple", "expert": "pro", "": "", "other": ""} {
		if got := levelOf(in); got != want {
			t.Errorf("levelOf(%q) = %q, want %q", in, got, want)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AppData", t.TempDir())
	// fresh install: nothing is decided, nothing is written
	if st := migrateUIState(); st["shunt-level"] != "" {
		t.Fatalf("fresh install got a level: %v", st)
	}
	v := "expert"
	if _, err := mergeUIState(map[string]*string{"shunt-view-mode": &v}); err != nil {
		t.Fatal(err)
	}
	if st := migrateUIState(); st["shunt-level"] != "pro" || st["shunt-view-mode"] != "expert" {
		t.Fatalf("expert not migrated: %v", st)
	}
	if got := loadUIState()["shunt-level"]; got != "pro" {
		t.Fatalf("level not saved: %q", got)
	}
	// a level chosen later wins over the old key
	l := "opsec"
	if _, err := mergeUIState(map[string]*string{"shunt-level": &l}); err != nil {
		t.Fatal(err)
	}
	if st := migrateUIState(); st["shunt-level"] != "opsec" {
		t.Fatalf("chosen level overwritten: %v", st)
	}
}
