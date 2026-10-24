package winsplit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = kernel32.NewProc("IsProcessInJob")
	procOpenJobObject  = kernel32.NewProc("OpenJobObjectW")
)

const (
	jobAssign = 0x1 // JOB_OBJECT_ASSIGN_PROCESS
	jobQuery  = 0x4 // JOB_OBJECT_QUERY
	// a process to pin must have been started this recently (it waits,
	// suspended, for the service)
	pinMaxAge = 10 * time.Second
)

// Jobs keeps the processes started in a route ("run --via"): each start gets
// a job object of its own, its children inherit it (like a cgroup on Linux).
// Jobs are named, and the names are kept in a file, so a restarted service
// finds the processes of its predecessor again.
type Jobs struct {
	// State is the file the job names are kept in ("" = not kept).
	State string

	mu   sync.Mutex
	jobs []job
}

type job struct {
	Name  string `json:"name"`
	Route string `json:"route"`
	h     windows.Handle
}

// Load opens the jobs of the state file that still exist.
func (j *Jobs) Load() {
	b, err := os.ReadFile(j.State)
	if err != nil {
		return
	}
	var saved []job
	if json.Unmarshal(b, &saved) != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, s := range saved {
		if !strings.HasPrefix(s.Name, `Global\TheShunt-run-`) || s.Route == "" {
			continue
		}
		name, err := windows.UTF16PtrFromString(s.Name)
		if err != nil {
			continue
		}
		h, _, _ := procOpenJobObject.Call(jobAssign|jobQuery, 0, uintptr(unsafe.Pointer(name)))
		if h == 0 {
			continue // its processes are gone
		}
		s.h = windows.Handle(h)
		j.jobs = append(j.jobs, s)
	}
	j.saveLocked()
}

func (j *Jobs) saveLocked() {
	if j.State == "" {
		return
	}
	b, _ := json.Marshal(j.jobs)
	tmp := j.State + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, j.State)
	}
}

// Pin puts a process that was just started (suspended) into a new job with
// route. The caller resumes it afterwards.
func (j *Jobs) Pin(pid uint32, route string) error {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("process %d: %w", pid, err)
	}
	defer windows.CloseHandle(p)
	var created, x1, x2, x3 windows.Filetime
	if err := windows.GetProcessTimes(p, &created, &x1, &x2, &x3); err != nil {
		return err
	}
	if age := time.Since(time.Unix(0, created.Nanoseconds())); age > pinMaxAge {
		return fmt.Errorf("process %d runs for %s already: only a process that was just started can be put into a route", pid, age.Round(time.Second))
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if r := j.routeLocked(p); r != "" {
		return fmt.Errorf("process %d is in route %s already", pid, r)
	}
	rnd := make([]byte, 8)
	_, _ = rand.Read(rnd)
	name := `Global\TheShunt-run-` + hex.EncodeToString(rnd)
	np, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateJobObject(nil, np) // default DACL: SYSTEM and Administrators
	if err != nil {
		return fmt.Errorf("job object: %w", err)
	}
	if err := windows.AssignProcessToJobObject(h, p); err != nil {
		windows.CloseHandle(h)
		return fmt.Errorf("process %d into its route: %w", pid, err)
	}
	j.jobs = append(j.jobs, job{Name: name, Route: route, h: h})
	j.saveLocked()
	return nil
}

func inJob(p, h windows.Handle) bool {
	var in int32
	r, _, _ := procIsProcessInJob.Call(uintptr(p), uintptr(h), uintptr(unsafe.Pointer(&in)))
	return r != 0 && in != 0
}

func (j *Jobs) routeLocked(p windows.Handle) string {
	for i := len(j.jobs) - 1; i >= 0; i-- { // the newest first: jobs may be nested
		if inJob(p, j.jobs[i].h) {
			return j.jobs[i].Route
		}
	}
	return ""
}

// Route returns the route process pid was started in, "" = none.
func (j *Jobs) Route(pid uint32) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.jobs) == 0 {
		return ""
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(p)
	return j.routeLocked(p)
}

// jobAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type jobAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodUserTime, ThisPeriodKernelTime int64
	TotalPageFaults, TotalProcesses, ActiveProcesses, TotalTerminated        uint32
}

// Cleanup drops the jobs whose processes have all ended.
func (j *Jobs) Cleanup() {
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := j.jobs[:0]
	for _, jb := range j.jobs {
		var a jobAccounting
		err := windows.QueryInformationJobObject(jb.h, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&a)), uint32(unsafe.Sizeof(a)), nil)
		if err == nil && a.ActiveProcesses == 0 {
			windows.CloseHandle(jb.h)
			continue
		}
		kept = append(kept, jb)
	}
	if len(kept) != len(j.jobs) {
		j.jobs = kept
		j.saveLocked()
	} else {
		j.jobs = kept
	}
}

// Proc is a running process.
type Proc struct {
	PID  uint32
	Exe  string // file name, as in the process list ("brave.exe")
	Path string // full path, lower case ("" = not readable)
}

// Processes lists the running processes whose file name is exe (case
// insensitive; "" = all).
func Processes(exe string) ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Proc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		name := windows.UTF16ToString(e.ExeFile[:])
		if exe != "" && !strings.EqualFold(name, exe) {
			continue
		}
		out = append(out, Proc{PID: e.ProcessID, Exe: name, Path: exePath(e.ProcessID)})
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		err = nil
	}
	return out, err
}
