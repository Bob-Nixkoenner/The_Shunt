package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense/evidence"
)

func TestEvidenceVerifyCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	l, err := evidence.Open(dir, evidence.Options{Version: "v-test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = l.Append(evidence.Input{Kind: "scan", Severity: "high", Src: "192.0.2.5"})
	}
	l.Close()
	if err := evidenceCmd([]string{"verify", dir}); err != nil {
		t.Fatal(err)
	}
	// export, then verify the archive and a damaged copy
	res, err := evidence.Export(t.Context(), evidence.ExportOptions{Dir: dir, Src: "192.0.2.5", OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := evidenceCmd([]string{"verify", res.Path}); err != nil {
		t.Fatal(err)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	b, _ := os.ReadFile(names[0])
	_ = os.WriteFile(names[0], []byte(strings.Replace(string(b), "192.0.2.5", "192.0.2.6", 1)), 0o600)
	if err := evidenceCmd([]string{"verify", dir}); err == nil || !strings.Contains(err.Error(), "events-") {
		t.Fatalf("damage not reported with the place: %v", err)
	}
	if evidenceCmd([]string{"verify"}) == nil || evidenceCmd([]string{"nonsense", dir}) == nil {
		t.Fatal("bad usage accepted")
	}
}
