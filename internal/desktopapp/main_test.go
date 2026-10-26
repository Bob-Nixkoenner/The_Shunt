package desktopapp

import (
	"os"
	"testing"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// The tests read English texts whatever the language of the machine is.
func TestMain(m *testing.M) {
	i18n.Set("en")
	os.Exit(m.Run())
}

func TestGermanTexts(t *testing.T) {
	i18n.Set("de")
	defer i18n.Set("en")
	v := Compute(nil, os.ErrNotExist, time.Now())
	if !v.Unreachable || v.Title != "Der Dienst von The Shunt ist nicht erreichbar" {
		t.Errorf("view = %+v", v)
	}
}
