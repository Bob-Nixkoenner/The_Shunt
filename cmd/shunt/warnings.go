package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/check"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// warningsCmd: the warnings the user hid (check/ignore.go).
//
//	shunt warnings                          list them
//	shunt warnings hide KEY day|week|forever
//	shunt warnings show KEY                 show it again
func warningsCmd(c *api.Client, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		var ls []check.Ignored
		if err := c.Do("GET", "/v1/warnings/ignored", nil, &ls); err != nil {
			return err
		}
		if len(ls) == 0 {
			fmt.Println(i18n.T("No warnings hidden."))
			return nil
		}
		for _, it := range ls {
			until := i18n.T("for good")
			if !it.Until.IsZero() {
				until = i18n.T("until {time}", "time", it.Until.Local().Format(time.DateTime))
			}
			fmt.Printf("%s  (%s)\n      %s\n", it.Key, until, check.Finding{Msg: it.Msg, Vals: it.Vals}.Local())
		}
		return nil
	}
	switch {
	case args[0] == "hide" && len(args) == 3:
		if _, err := check.ParseFor(args[2]); err != nil {
			return err
		}
		return c.Do("POST", "/v1/warnings/ignore", api.IgnoreRequest{Key: args[1], For: args[2]}, nil)
	case args[0] == "show" && len(args) == 2:
		return c.Do("DELETE", "/v1/warnings/ignore?key="+url.QueryEscape(args[1]), nil, nil)
	}
	flag.Usage()
	os.Exit(2)
	return errors.New("usage")
}

// hiddenLine: "n warnings hidden" for status and check (hidden is not fixed).
func hiddenLine(st *api.Status) string {
	if len(st.Ignored) == 0 {
		return ""
	}
	return i18n.Tn(len(st.Ignored), "{n} warning hidden (shunt warnings)", "{n} warnings hidden (shunt warnings)")
}
