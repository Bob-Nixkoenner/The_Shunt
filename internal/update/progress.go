package update

import (
	"strings"
	"time"
)

// installSteps are the headings install.sh prints (say "..."), in order. The
// update button shows how far the installer got from them.
var installSteps = []string{
	"Please note",
	"Checking the system",
	"Checking the network",
	"Installing dependencies",
	"Configuration",
	"Dry run",
	"Starting the service",
}

// stallAfter: a running installer that wrote nothing for this long is
// reported as quiet (a package download or build can take minutes).
const stallAfter = 5 * time.Minute

// Progress is the state of an update started by Apply.
type Progress struct {
	// State: "idle" (none started), "running", "done", "failed".
	State string `json:"state"`
	Step  int    `json:"step"`  // installer step now running, 1-based
	Total int    `json:"total"` // number of steps
	// Text: what runs now (heading, or the long task inside it).
	Text string `json:"text,omitempty"`
	// Error: why it failed (the installer's last error line).
	Error string `json:"error,omitempty"`
	// Quiet: running, but no output for a while.
	Quiet bool   `json:"quiet,omitempty"`
	Log   string `json:"log,omitempty"` // where the full output is
}

// parseProgress is GetProgress for the log text, whether the installer
// process lives and how long ago the log was written.
func parseProgress(log string, alive bool, age time.Duration, logPath string) Progress {
	p := Progress{State: "running", Total: len(installSteps), Log: logPath}
	result := ""
	for _, l := range strings.Split(log, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "==> "):
			name := strings.TrimPrefix(l, "==> ")
			p.Text = name
			for i, s := range installSteps {
				if s == name && i+1 > p.Step {
					p.Step = i + 1
				}
			}
		case strings.HasPrefix(l, "... "):
			p.Text = strings.TrimPrefix(l, "... ")
		case strings.HasPrefix(l, "SHUNT-RESULT "):
			result = strings.TrimPrefix(l, "SHUNT-RESULT ")
		case strings.HasPrefix(l, "ERROR:"):
			p.Error = strings.TrimSpace(strings.TrimPrefix(l, "ERROR:"))
		}
	}
	switch {
	case result == "ok":
		p.State, p.Step, p.Error = "done", p.Total, ""
	case result == "failed":
		p.State = "failed"
	case !alive:
		// gone without a result: killed, or pkexec was cancelled
		p.State = "failed"
		if p.Error == "" {
			p.Error = "the installer stopped without finishing"
		}
	default:
		p.Quiet = age > stallAfter
	}
	if p.State == "failed" && p.Error == "" {
		p.Error = "the installer failed (see the log)"
	}
	return p
}
