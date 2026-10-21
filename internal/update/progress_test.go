package update

import (
	"testing"
	"time"
)

func TestParseProgress(t *testing.T) {
	const head = "==> Please note\n  text\n==> Checking the system\n  ✔ ok\n==> Checking the network\n==> Installing dependencies\n  ... installing nftables (apt)\n"
	tests := []struct {
		name  string
		log   string
		alive bool
		age   time.Duration
		want  Progress
	}{
		{"running", head, true, time.Second, Progress{State: "running", Step: 4, Text: "installing nftables (apt)"}},
		{"quiet", head, true, 6 * time.Minute, Progress{State: "running", Step: 4, Text: "installing nftables (apt)", Quiet: true}},
		{"done", head + "==> Starting the service\nSHUNT-RESULT ok\n", false, time.Second, Progress{State: "done", Step: 7, Text: "Starting the service"}},
		{"failed with reason", head + "==> Dry run\nERROR: configuration check failed - fix it\nSHUNT-RESULT failed\n", false, time.Second,
			Progress{State: "failed", Step: 6, Text: "Dry run", Error: "configuration check failed - fix it"}},
		{"killed", head, false, time.Second, Progress{State: "failed", Step: 4, Text: "installing nftables (apt)", Error: "the installer stopped without finishing"}},
		{"started again after a re-exec", head + "==> Please note\n", true, time.Second, Progress{State: "running", Step: 4, Text: "Please note"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProgress(tt.log, tt.alive, tt.age, "")
			tt.want.Total = len(installSteps)
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
