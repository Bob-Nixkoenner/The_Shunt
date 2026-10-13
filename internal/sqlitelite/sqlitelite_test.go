package sqlitelite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRowsBig(t *testing.T) {
	rows, err := Rows("testdata/big.sqlite", "Profiles")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 401 {
		t.Fatalf("%d rows", len(rows))
	}
	names := map[string]bool{}
	for _, r := range rows {
		names[r["name"].(string)] = true
		if r["path"] == "long.path" && r["name"] != strings.Repeat("L", 5000) {
			t.Error("overflow payload wrong")
		}
	}
	if !names["name 1"] || !names["name 400"] {
		t.Error("rows missing")
	}
	other, err := Rows("testdata/big.sqlite", "other")
	if err != nil || len(other) != 1 || other[0]["x"] != int64(-5) || other[0]["y"] != "neg" {
		t.Fatalf("%v %v", other, err)
	}
	if _, err := Rows("testdata/big.sqlite", "nope"); err == nil {
		t.Error("missing table not reported")
	}
}

// A change still in the write-ahead log counts.
func TestRowsWAL(t *testing.T) {
	rows, err := Rows("testdata/wal.sqlite", "Profiles")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r["path"].(string)] = r["name"].(string)
	}
	if got["a.default"] != "privat" || got["b.Profil 1"] != "SM" {
		t.Fatalf("%v", got)
	}
}

func TestColumns(t *testing.T) {
	c := columns(`CREATE TABLE "P" (id INTEGER NOT NULL, "path" TEXT UNIQUE, n NUMERIC(10,2), PRIMARY KEY(id))`)
	if strings.Join(c, ",") != "id,path,n" {
		t.Error(c)
	}
}

func FuzzRows(f *testing.F) {
	f.Add([]byte("SQLite format 3\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = record(b)
		_, _ = varint(b)
	})
}

// A damaged database file must give an error, never a panic or a hang.
func FuzzFile(f *testing.F) {
	for _, s := range []string{"testdata/big.sqlite", "testdata/wal.sqlite"} {
		b, err := os.ReadFile(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(dir, "x.sqlite")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = Rows(p, "Profiles")
		_, _ = Rows(p, "other")
	})
}
