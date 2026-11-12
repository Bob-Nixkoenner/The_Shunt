// Package systemd_test checks the unit files against what shuntd needs.
package systemd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unit reads the [Service] settings of shuntd.service; a key that is set
// several times keeps all its values, split at white space.
func unit(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("shuntd.service")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("line without '=': %q", l)
		}
		out[k] = append(out[k], strings.Fields(v)...)
	}
	return out
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// The evidence log reads the clock state with adjtimex (read-only). Max
// Security turns the log on; a unit that does not let the call through
// killed shuntd at every start (SIGSYS, 2026-11-12).
func TestUnitLetsTheClockStateBeRead(t *testing.T) {
	u := unit(t)
	if !has(u["SystemCallFilter"], "adjtimex") {
		t.Error("SystemCallFilter lacks adjtimex: evidence.ClockSynced is killed or refused")
	}
	// ProtectClock adds a filter of its own that refuses the whole @clock
	// group, adjtimex in read-only mode included.
	if has(u["ProtectClock"], "yes") || has(u["ProtectClock"], "true") {
		t.Error("ProtectClock=yes refuses adjtimex even when SystemCallFilter allows it")
	}
	// what keeps the clock from being set instead
	for _, c := range u["CapabilityBoundingSet"] {
		if c == "CAP_SYS_TIME" || c == "CAP_WAKE_ALARM" || strings.HasPrefix(c, "~") {
			t.Errorf("CapabilityBoundingSet %q: the clock must stay out of reach", c)
		}
	}
	if !has(u["NoNewPrivileges"], "yes") {
		t.Error("NoNewPrivileges=yes is what keeps CAP_SYS_TIME from coming back")
	}
	for _, c := range []string{"settimeofday", "clock_settime", "clock_adjtime", "@clock"} {
		if has(u["SystemCallFilter"], c) {
			t.Errorf("SystemCallFilter allows %s", c)
		}
	}
}

// A call outside the list must fail, not kill: a killed daemon restarts
// into the same call for ever and leaves no socket to change the setting.
func TestUnitRefusesInsteadOfKilling(t *testing.T) {
	u := unit(t)
	if got := u["SystemCallErrorNumber"]; len(got) != 1 || got[0] != "EPERM" {
		t.Errorf("SystemCallErrorNumber = %v, want EPERM", got)
	}
	if !has(u["SystemCallFilter"], "@system-service") {
		t.Errorf("SystemCallFilter is no longer the allow-list the checks here assume: %v", u["SystemCallFilter"])
	}
	for _, c := range u["SystemCallFilter"] {
		if strings.HasPrefix(c, "~") {
			t.Errorf("SystemCallFilter %q: a deny-list entry, the checks here assume an allow-list", c)
		}
	}
}

// TestUnitAllowsTheCallsShuntdMakes compares the system calls that shuntd's
// own code and its libraries name (unix.Xxx(...), unix.SYS_XXX) with what
// the unit's SystemCallFilter lets through, expanded by systemd-analyze.
// The 2026-11-12 crash loop (adjtimex, only reached with evidence on) went
// past review, unit tests and the lab, because no test started shuntd under
// the real unit with that path switched on; this test does not need to.
// Limits: the Go runtime and the standard library are not covered (checked
// once by disassembly, 2026-11-12), nor child programs (tor, nft, ...).
func TestUnitAllowsTheCallsShuntdMakes(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze missing")
	}
	groups, known := syscallGroups(t)
	allowed := map[string]bool{}
	var add func(string)
	add = func(n string) {
		if strings.HasPrefix(n, "@") {
			for _, m := range groups[n] {
				add(m)
			}
			return
		}
		allowed[n] = true
	}
	for _, n := range unit(t)["SystemCallFilter"] {
		add(n)
	}
	if len(allowed) < 100 {
		t.Fatalf("expanded filter has only %d calls, systemd-analyze output not understood", len(allowed))
	}

	// what the code may call, together with where
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles \",\"}}{{end}}", "../../cmd/shuntd")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	call := regexp.MustCompile(`\b(?:unix|syscall)\.(?:SYS_([A-Z0-9_]+)\b|([A-Z][A-Za-z0-9]*)\()`)
	missing := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(l, "|", 3)
		if len(parts) != 3 || skipPkg(parts[0]) {
			continue
		}
		for _, f := range strings.Split(parts[2], ",") {
			b, err := os.ReadFile(filepath.Join(parts[1], f))
			if err != nil {
				continue
			}
			for _, m := range call.FindAllStringSubmatch(string(b), -1) {
				if strings.Contains(m[2], "Syscall") {
					continue // the raw dispatcher, its number is matched as SYS_XXX
				}
				name := strings.ToLower(m[1])
				if name == "" {
					name = snake(m[2])
				}
				for _, n := range []string{name, strings.ReplaceAll(name, "_", "")} {
					if known[n] && !allowed[n] {
						if _, ok := missing[n]; !ok {
							missing[n] = parts[0] + "/" + f
						}
					}
				}
			}
		}
	}
	for n, where := range missing {
		if !expectedOutside[n] {
			t.Errorf("%s (named in %s) is outside SystemCallFilter: allow it in shuntd.service or add it to expectedOutside with the reason", n, where)
		}
	}
}

// Calls named in the code that the unit leaves out on purpose; with
// SystemCallErrorNumber=EPERM they fail instead of killing shuntd.
var expectedOutside = map[string]bool{
	// child process start (os/exec, x/sys), only with settings shuntd never uses
	"ptrace": true, "chroot": true, "mount": true, "unshare": true, "setns": true,
	// mdlayher/socket offers Conn.PidfdGetfd; shuntd never calls it
	"pidfd_getfd": true,
}

// skipPkg leaves out the packages that only define the wrappers.
func skipPkg(p string) bool {
	return strings.HasPrefix(p, "golang.org/x/sys/") || strings.HasSuffix(p, "/internal/unix")
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// syscallGroups reads every group of systemd-analyze and all known calls.
func syscallGroups(t *testing.T) (map[string][]string, map[string]bool) {
	t.Helper()
	cmd := exec.Command("systemd-analyze", "syscall-filter", "--no-pager")
	cmd.Env = append(os.Environ(), "SYSTEMD_COLORS=0")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("systemd-analyze: %v", err)
	}
	esc := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	groups := map[string][]string{}
	known := map[string]bool{}
	cur := ""
	for _, l := range strings.Split(esc.ReplaceAllString(string(out), ""), "\n") {
		f := strings.TrimSpace(l)
		switch {
		case f == "" || strings.HasPrefix(f, "#"):
		case !strings.HasPrefix(l, " "):
			cur = f
		default:
			groups[cur] = append(groups[cur], f)
			if !strings.HasPrefix(f, "@") {
				known[f] = true
			}
		}
	}
	return groups, known
}
