package main

import (
	"errors"
	"fmt"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense/evidence"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// evidenceCmd: `shunt evidence verify <archive|dir>`. It reads files only
// (no service, no network): a case archive (.tar.gz), an unpacked archive or
// the evidence directory itself. Exit status 1 when anything does not match.
func evidenceCmd(args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return errors.New(i18n.T("usage: shunt evidence verify <archive.tar.gz | directory>"))
	}
	r, err := evidence.VerifyPath(args[1])
	if err != nil {
		return err
	}
	for _, n := range r.Notes {
		fmt.Println(i18n.T("note: {text}", "text", n))
	}
	if !r.OK {
		for _, p := range r.Problems {
			fmt.Println(i18n.T("PROBLEM: {text}", "text", p))
		}
		return errors.New(i18n.T("evidence verify: FAILED, first problem at {where}", "where", r.FirstBad))
	}
	fmt.Println(i18n.T("evidence verify: OK ({lines} lines, {files} files)", "lines", r.Lines, "files", r.Files))
	return nil
}
