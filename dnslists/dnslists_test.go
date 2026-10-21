package dnslists

import (
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/DNS-LISTS.md")

const page = "../docs/DNS-LISTS.md"

func TestDefaultsParse(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.For(1, "linux")) == 0 || len(d.For(2, "linux")) == 0 || len(d.For(3, "linux")) == 0 {
		t.Error("a level has no lists")
	}
}

func TestPageUpToDate(t *testing.T) {
	d, _ := Load()
	want := Markdown(d)
	if *update {
		if err := os.WriteFile(page, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(page)
	if err != nil || string(got) != want {
		t.Fatal("docs/DNS-LISTS.md is out of date: run  go test ./dnslists -update")
	}
}
