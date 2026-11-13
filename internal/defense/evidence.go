package defense

import (
	"fmt"
	"net/url"
)

// Evidence settings and the hook that feeds the evidence log. The log itself
// lives in package evidence (internal/defense/evidence); the manager only
// calls the hook, so nothing here depends on it.

// EvidenceConfig is [defense.evidence]. The zero value is "off".
type EvidenceConfig struct {
	// Enabled writes every event to the local evidence log (JSON lines with
	// a hash chain, mode 0600). Default off: addresses of other people are
	// personal data, so it is the user's choice.
	Enabled bool `json:"enabled" toml:"enabled"`
	// RetentionDays is how long log files are kept (default 90). A pinned
	// case stays until the user deletes it.
	RetentionDays int `json:"retention_days,omitempty" toml:"retention_days,omitempty"`
	// MaxMB caps the size of the log (default 512). The oldest files go
	// first; pinned cases are exempt.
	MaxMB int `json:"max_mb,omitempty" toml:"max_mb,omitempty"`
	// Capture switches the packet capture on (Linux only, default off):
	// unsolicited inbound packets and link-layer control frames, kept in
	// memory and written to disk only around an event of severity medium or
	// above.
	Capture bool `json:"capture,omitempty" toml:"capture,omitempty"`
	// CaptureMaxMB caps the capture files (default 100).
	CaptureMaxMB int `json:"capture_max_mb,omitempty" toml:"capture_max_mb,omitempty"`
	// TSAURL is an optional RFC 3161 time stamp authority (https). Used only
	// when the user exports a case; only a hash is sent.
	TSAURL string `json:"tsa_url,omitempty" toml:"tsa_url,omitempty"`
}

// Evidence defaults.
const (
	DefaultEvidenceRetentionDays = 90
	DefaultEvidenceMaxMB         = 512
	DefaultEvidenceCaptureMaxMB  = 100
)

// Normalized fills the defaults.
func (e EvidenceConfig) Normalized() EvidenceConfig {
	if e.RetentionDays <= 0 {
		e.RetentionDays = DefaultEvidenceRetentionDays
	}
	if e.MaxMB <= 0 {
		e.MaxMB = DefaultEvidenceMaxMB
	}
	if e.CaptureMaxMB <= 0 {
		e.CaptureMaxMB = DefaultEvidenceCaptureMaxMB
	}
	return e
}

// ValidateEvidence checks [defense.evidence].
func ValidateEvidence(e EvidenceConfig) error {
	if e.RetentionDays < 0 || e.RetentionDays > 3650 {
		return fmt.Errorf("defense.evidence.retention_days %d (0 = default 90, at most 3650)", e.RetentionDays)
	}
	if e.MaxMB < 0 || e.MaxMB > 100000 {
		return fmt.Errorf("defense.evidence.max_mb %d (0 = default, at most 100000)", e.MaxMB)
	}
	if e.CaptureMaxMB < 0 || e.CaptureMaxMB > 100000 {
		return fmt.Errorf("defense.evidence.capture_max_mb %d (0 = default, at most 100000)", e.CaptureMaxMB)
	}
	if e.TSAURL != "" {
		u, err := url.Parse(e.TSAURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("defense.evidence.tsa_url must be an https URL without credentials")
		}
	}
	return nil
}

// WithEventHook calls f for every event that took a place in the ring (not
// for folded repeats), after it was counted, with the network class in
// effect. f must be quick and must not call back into the manager.
func WithEventHook(f func(Event, Class)) Option { return func(m *Manager) { m.onEvent = f } }

func (m *Manager) emitEvent(ev Event) {
	if m.onEvent == nil || ev.Trust != "" { // known/test sources are shown, not reported
		return
	}
	m.mu.Lock()
	c := m.class
	m.mu.Unlock()
	m.onEvent(ev, c)
}

// Name is the severity as written in the evidence log.
func (s Severity) Name() string {
	switch s {
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	}
	return "info"
}

// DecoyPorts lists the ports the decoys listen on now.
func (m *Manager) DecoyPorts() []int { return m.dec.Ports() }
