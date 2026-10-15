//go:build !windows

package desktopapp

import (
	"fmt"
	"os"
)

func defaultSocketName() string { return fmt.Sprintf("@the-shunt-desktop-%d", os.Getuid()) }
