package ui

import (
	"fmt"
	"os"
	"testing"
)

// I18N_DUMP=1 go test ./internal/ui -run TestDumpTexts -v lists the texts
// to translate (a tool for whoever adds a language or new texts).
func TestDumpTexts(t *testing.T) {
	if os.Getenv("I18N_DUMP") == "" {
		t.Skip("set I18N_DUMP=1")
	}
	sure, maybe := scriptTexts()
	fmt.Println("=== HTML")
	for _, s := range pageTexts() {
		fmt.Println(s)
	}
	fmt.Println("=== T()")
	for _, s := range sure {
		fmt.Println(s)
	}
	fmt.Println("=== JS?")
	for _, s := range maybe {
		fmt.Println(s)
	}
}
