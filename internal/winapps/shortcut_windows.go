package winapps

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// MakeShortcut writes a .lnk through the shell's own COM object (WScript.Shell
// in PowerShell). The values go in as environment variables, never as part
// of the script.
func MakeShortcut(sc Shortcut) error {
	const script = `$ErrorActionPreference = 'Stop'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SHUNT_LNK)
$s.TargetPath = $env:SHUNT_TARGET
$s.Arguments = $env:SHUNT_ARGS
$s.WorkingDirectory = $env:SHUNT_DIR
$s.IconLocation = $env:SHUNT_ICON
$s.Description = $env:SHUNT_DESC
$s.Save()`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(),
		"SHUNT_LNK="+sc.Path, "SHUNT_TARGET="+sc.Target, "SHUNT_ARGS="+sc.Args,
		"SHUNT_DIR="+sc.Dir, "SHUNT_ICON="+sc.Icon, "SHUNT_DESC="+sc.Description)
	const createNoWindow = 0x08000000
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("shortcut %s: %v: %s", sc.Path, err, strings.TrimSpace(string(out)))
	}
	return nil
}
