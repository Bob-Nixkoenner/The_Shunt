package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense/evidence"
)

// Evidence log and capture (package internal/defense/evidence). Everything
// stays in <state>/defense/evidence (0700, files 0600); nothing leaves the
// machine except on a user action (export download, abuse lookup, optional
// time stamp). The Shunt never scans back.

// evState is the daemon's evidence state; zero value = off.
type evState struct {
	mu      sync.RWMutex
	log     *evidence.Log
	watch   *evidence.StateWatch
	cap     *evidence.Capture
	cfg     defense.EvidenceConfig
	abuse   *evidence.Abuser
	stopRun context.CancelFunc
	capIf   string
	capStop context.CancelFunc
	cases   *evidence.Cases
}

// evidenceDir is in the state directory when systemd gives one (evidence
// must not sit in a cache directory that may be cleaned), else next to the
// other defense files.
func (d *Daemon) evidenceDir() string {
	if s, _, _ := strings.Cut(os.Getenv("STATE_DIRECTORY"), ":"); s != "" {
		return filepath.Join(s, "evidence")
	}
	return filepath.Join(d.defenseDir(), "evidence")
}

// evidenceSkip lists the event kinds that are not written: they describe
// what the user's own programs do (destinations, app names, queried
// domains) and not what reached the machine.
var evidenceSkip = map[defense.Kind]bool{
	defense.KindFirstSeen: true, defense.KindBeacon: true, defense.KindObservation: true,
	defense.KindDNSTunnel: true, defense.KindDNSRebind: true,
}

// evidenceEvent is the manager's event hook.
func (d *Daemon) evidenceEvent(ev defense.Event, class defense.Class) {
	e := &d.def.ev
	e.mu.RLock()
	l, w, c := e.log, e.watch, e.cap
	e.mu.RUnlock()
	if l == nil || evidenceSkip[ev.Kind] {
		return
	}
	l.SetNetClass(string(class))
	if ev.Kind == defense.KindNetEnter && w != nil {
		w.SetNet(string(class), ev.Time)
	}
	src := ev.Src
	if a, err := netip.ParseAddr(src); err == nil && ownAddr(a) {
		src = "" // never an address of this machine
	}
	seq, err := l.Append(evidence.Input{Time: ev.Time, Kind: string(ev.Kind), Severity: ev.Severity.Name(), Src: src,
		Port: ev.Port, Proto: ev.Proto, Detail: evidence.ScrubDetail(ev.Detail)})
	if err != nil {
		d.Log.Debug("evidence: log write", "err", err)
		return
	}
	if c != nil && ev.Severity >= defense.SevMedium {
		if err := c.Trigger(seq); err != nil {
			d.Log.Debug("evidence: capture write", "err", err)
		}
	}
}

// evidencePacket takes the first packet of a new inbound connection (from
// the NFLOG group) for the capture when it is unsolicited: to a decoy port
// or a port nothing listens on.
func (d *Daemon) evidencePacket(payload []byte, proto string, port int, listen map[string]bool) {
	d.def.ev.mu.RLock()
	c := d.def.ev.cap
	d.def.ev.mu.RUnlock()
	if c == nil || d.def.m == nil {
		return
	}
	if evidence.InboundWanted(proto, port, d.def.m.DecoyPorts(), func(p string, n int) bool { return listen[fmt.Sprint(p, "/", n)] }) {
		c.Packet(evidence.IfInbound, payload, len(payload))
	}
}

// evidenceApply applies [defense.evidence]. Called by defenseApply (reload,
// d.mu held), so it only does quick work.
func (d *Daemon) evidenceApply(cfg defense.EvidenceConfig, defenseOn bool) {
	cfg = cfg.Normalized()
	e := &d.def.ev
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	if e.abuse == nil {
		e.abuse = &evidence.Abuser{CacheFile: filepath.Join(d.evidenceDir(), evidence.AbuseCacheName)}
	}
	on := cfg.Enabled && defenseOn
	if !on {
		d.evidenceStopLocked()
		return
	}
	if e.log == nil {
		w := &evidence.StateWatch{Synced: evidence.ClockSynced}
		l, err := evidence.Open(d.evidenceDir(), evidence.Options{Version: d.Version, Preamble: w.Preamble})
		if err != nil {
			d.Log.Warn("evidence: cannot open the log", "err", err)
			return
		}
		w.Log = l
		e.log, e.watch = l, w
		ctx, cancel := context.WithCancel(context.Background())
		e.stopRun = cancel
		go d.evidenceRun(ctx)
		d.Log.Info("evidence: log on")
	}
	if cfg.Capture && evidence.CaptureSupported {
		if e.cap == nil {
			e.cap = &evidence.Capture{Dir: filepath.Join(d.evidenceDir(), evidence.PcapDir), Protect: d.evCasesLocked().Protects}
		}
		e.cap.MaxBytes = int64(cfg.CaptureMaxMB) << 20
	} else if e.cap != nil {
		d.evidenceStopCaptureLocked()
	}
}

func (d *Daemon) evidenceStopCaptureLocked() {
	e := &d.def.ev
	if e.capStop != nil {
		e.capStop()
		e.capStop, e.capIf = nil, ""
	}
	if e.cap != nil {
		e.cap.Close()
		e.cap = nil
	}
}

func (d *Daemon) evidenceStopLocked() {
	e := &d.def.ev
	d.evidenceStopCaptureLocked()
	if e.stopRun != nil {
		e.stopRun()
		e.stopRun = nil
	}
	if e.log != nil {
		_ = e.log.Close()
		e.log, e.watch = nil, nil
	}
}

func (d *Daemon) stopEvidence() {
	d.def.ev.mu.Lock()
	d.evidenceStopLocked()
	d.def.ev.mu.Unlock()
}

// evidenceRun is the maintenance loop: capture window and interface,
// clock checks every 30 s, retention every hour.
func (d *Daemon) evidenceRun(ctx context.Context) {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		n++
		e := &d.def.ev
		e.mu.Lock()
		l, w, c, cfg := e.log, e.watch, e.cap, e.cfg
		if c != nil {
			if ifc := d.defIface(); ifc != "" && ifc != e.capIf {
				if e.capStop != nil {
					e.capStop()
				}
				cctx, cancel := context.WithCancel(context.Background())
				e.capStop, e.capIf = cancel, ifc
				go func() {
					if err := evidence.RunControl(cctx, ifc, c); err != nil && cctx.Err() == nil {
						d.Log.Debug("evidence: control frame capture", "err", err)
					}
				}()
			}
		}
		e.mu.Unlock()
		if c != nil {
			c.Tick()
		}
		if w != nil && n%6 == 0 {
			w.Check()
		}
		if l != nil && (n == 2 || n%720 == 0) {
			if _, err := l.Prune(time.Duration(cfg.RetentionDays)*24*time.Hour, int64(cfg.MaxMB)<<20, d.evCases().Protects); err != nil {
				d.Log.Debug("evidence: retention", "err", err)
			}
		}
	}
}

func (d *Daemon) evCasesLocked() *evidence.Cases {
	e := &d.def.ev
	if e.cases == nil {
		if err := evidence.SafeDir(d.evidenceDir()); err == nil {
			e.cases, _ = evidence.OpenCases(d.evidenceDir())
		}
		if e.cases == nil {
			e.cases = &evidence.Cases{}
		}
	}
	return e.cases
}

func (d *Daemon) evCases() *evidence.Cases {
	d.def.ev.mu.Lock()
	defer d.def.ev.mu.Unlock()
	return d.evCasesLocked()
}

// evidenceStatus is GET /v1/defense/evidence.
type evidenceStatusResp struct {
	Enabled  bool                   `json:"enabled"`
	Capture  bool                   `json:"capture"`
	Supports bool                   `json:"capture_supported"`
	Config   defense.EvidenceConfig `json:"config"`
	Status   evidence.Status        `json:"status"`
	Cases    []evidence.Case        `json:"cases"`
}

func (d *Daemon) evidenceStatus() evidenceStatusResp {
	e := &d.def.ev
	e.mu.RLock()
	l, cfg, c := e.log, e.cfg, e.cap
	e.mu.RUnlock()
	r := evidenceStatusResp{Enabled: l != nil, Capture: c != nil, Supports: evidence.CaptureSupported, Config: cfg.Normalized(), Cases: d.evCases().List()}
	if l != nil {
		r.Status = l.Status()
	} else if _, err := os.Stat(d.evidenceDir()); err == nil {
		r.Status = evidence.StatusOfDir(d.evidenceDir())
	}
	return r
}

type evCaseReq struct {
	Action string `json:"action"` // create, pin, unpin, delete
	ID     string `json:"id"`
	Name   string `json:"name"`
	Src    string `json:"src"`
}

type evPurgeReq struct {
	// All also removes pinned cases. Without it only what no pinned case holds goes.
	All bool `json:"all"`
}

type evExportReq struct {
	CaseID string `json:"case_id"`
	Src    string `json:"src"`
}

type evDownload struct {
	Name string `json:"name"`
	Size int    `json:"size"`
	Data []byte `json:"data"` // base64 in JSON
}

// maxDownload is the biggest archive handed to the UI as a download.
const maxDownload = 128 << 20

var exportName = regexp.MustCompile(`^shunt-case-[A-Za-z0-9._-]+\.tar\.gz$`)

// withEvidenceLog runs f with the open log, or with a temporary one.
func (d *Daemon) withEvidenceLog(f func(*evidence.Log) error) error {
	d.def.ev.mu.RLock()
	l := d.def.ev.log
	d.def.ev.mu.RUnlock()
	if l != nil {
		return f(l)
	}
	if _, err := os.Stat(d.evidenceDir()); err != nil {
		return nil // nothing recorded yet
	}
	t, err := evidence.Open(d.evidenceDir(), evidence.Options{Version: d.Version})
	if err != nil {
		return err
	}
	defer t.Close()
	return f(t)
}

func (d *Daemon) evidenceRoutes(mux *http.ServeMux) {
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if err := d.authorize(r.Context(), peerOf(r.Context())); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/defense/evidence", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.evidenceStatus())
	})
	mux.HandleFunc("POST /v1/defense/evidence/case", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req evCaseReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		cs := d.evCases()
		switch req.Action {
		case "create":
			a, err := netip.ParseAddr(strings.TrimSpace(req.Src))
			if err != nil {
				writeErr(w, http.StatusBadRequest, errors.New("src: not an IP address"))
				return
			}
			es, _ := evidence.ReadDir(d.evidenceDir(), evidence.Filter{Src: a.Unmap().String()})
			if len(es) == 0 {
				writeErr(w, http.StatusConflict, errors.New("no log lines of this address (is the evidence log on?)"))
				return
			}
			c, err := cs.Create(req.Name, a.String(), es[0].Seq)
			if err != nil {
				writeErr(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeJSON(w, http.StatusOK, c)
			return
		case "pin", "unpin":
			if err := cs.Pin(req.ID, req.Action == "pin"); err != nil {
				writeErr(w, http.StatusNotFound, err)
				return
			}
		case "delete":
			if err := cs.Delete(req.ID); err != nil {
				writeErr(w, http.StatusNotFound, err)
				return
			}
		default:
			writeErr(w, http.StatusBadRequest, errors.New("action: create, pin, unpin or delete"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/defense/evidence/purge", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req evPurgeReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		cs := d.evCases()
		n := 0
		err := d.withEvidenceLog(func(l *evidence.Log) error {
			var e error
			n, e = l.Purge(req.All, cs.Protects)
			return e
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if req.All { // a case without lines is of no use
			for _, c := range cs.List() {
				_ = cs.Delete(c.ID)
			}
		}
		writeJSON(w, http.StatusOK, map[string]int{"removed_files": n})
	})
	mux.HandleFunc("POST /v1/defense/evidence/export", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req evExportReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		o := evidence.ExportOptions{Dir: d.evidenceDir(), Version: d.Version, ClockSynced: evidence.ClockSynced}
		if req.CaseID != "" {
			c, ok := d.evCases().Get(req.CaseID)
			if !ok {
				writeErr(w, http.StatusNotFound, errors.New("no such case"))
				return
			}
			o.Case = &c
		} else {
			o.Src = req.Src
		}
		d.def.ev.mu.RLock()
		o.TSA = d.def.ev.cfg.TSAURL
		d.def.ev.mu.RUnlock()
		o.TSAClient = d.downloadClient()
		d.def.ev.mu.RLock()
		if l := d.def.ev.log; l != nil {
			_ = l.Sync()
		}
		d.def.ev.mu.RUnlock()
		res, err := evidence.Export(r.Context(), o)
		if err != nil {
			writeErr(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /v1/defense/evidence/download", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		name := r.URL.Query().Get("name")
		if !exportName.MatchString(name) || strings.Contains(name, "..") {
			writeErr(w, http.StatusBadRequest, errors.New("name: not an export archive"))
			return
		}
		p := filepath.Join(d.evidenceDir(), evidence.ExportsDir, name)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			writeErr(w, http.StatusNotFound, errors.New("no such archive"))
			return
		}
		if fi.Size() > maxDownload {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the archive is larger than %d MB; copy it from %s", maxDownload>>20, p))
			return
		}
		b, err := os.ReadFile(p)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, evDownload{Name: name, Size: len(b), Data: b})
	})
	mux.HandleFunc("GET /v1/defense/evidence/abuse", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		src := r.URL.Query().Get("src")
		if _, err := netip.ParseAddr(src); err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("src: not an IP address"))
			return
		}
		d.def.ev.mu.Lock()
		if d.def.ev.abuse == nil {
			d.def.ev.abuse = &evidence.Abuser{CacheFile: filepath.Join(d.evidenceDir(), evidence.AbuseCacheName)}
		}
		ab := d.def.ev.abuse
		d.def.ev.mu.Unlock()
		ab.Client = d.downloadClient() // the normal route
		info, err := ab.Lookup(r.Context(), src)
		if err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, evidence.ErrNotPublic) {
				code = http.StatusUnprocessableEntity
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	})
}
