package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/i18n"
)

// launcher is the program that starts apps in a route: this one (`run`),
// there is no CLI on Windows.
func launcher(self, _ string) string { return self }

var (
	procNtResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")
	procMessageBox      = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")
)

// runIn starts a program in a route, like `shunt run --via` on Linux: the
// program starts suspended, the service puts it into a job object of the
// route (its children inherit it), then it is woken up. Nothing of it runs
// before it is in its route; if the service says no, it never runs.
func runIn(sock string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	via := fs.String("via", "", "route: direct | block | tunnel:<name> | link:wifi|ethernet|mobile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := fs.Args()
	if *via == "" || len(cmd) == 0 {
		return errors.New("usage: shunt-desktop run --via ROUTE -- PROGRAM [ARGS...]")
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		return err
	}
	c := exec.Command(bin, cmd[1:]...)
	c.Dir = filepath.Dir(bin)
	const createSuspended = 0x4
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createSuspended}
	if err := c.Start(); err != nil {
		return err
	}
	pid := c.Process.Pid
	if err := api.NewClient(sock).Do("POST", "/v1/run", api.RunRequest{PID: pid, Route: *via}, nil); err != nil {
		_ = c.Process.Kill()
		return fmt.Errorf("%s via %s: %w", filepath.Base(bin), *via, err)
	}
	const suspendResume = 0x0800 // PROCESS_SUSPEND_RESUME
	h, err := windows.OpenProcess(suspendResume, false, uint32(pid))
	if err != nil {
		_ = c.Process.Kill()
		return err
	}
	defer windows.CloseHandle(h)
	if r, _, _ := procNtResumeProcess.Call(uintptr(h)); r != 0 {
		_ = c.Process.Kill()
		return fmt.Errorf("resume %s: NTSTATUS 0x%x", filepath.Base(bin), r)
	}
	return c.Process.Release()
}

// runFailed tells the user: a launcher from the Start menu has no console.
func runFailed(err error) {
	title, _ := windows.UTF16PtrFromString("The Shunt")
	msg, _ := windows.UTF16PtrFromString(i18n.T("Could not start the app in its route:\n\n{error}", "error", err.Error()))
	const iconError = 0x10
	procMessageBox.Call(0, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), iconError)
}
