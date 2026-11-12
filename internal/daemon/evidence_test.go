package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense"
	"github.com/Bob-Nixkoenner/the_shunt/internal/defense/evidence"
)

func evDaemon(t *testing.T) (*Daemon, *http.ServeMux) {
	t.Helper()
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	t.Setenv("CACHE_DIRECTORY", t.TempDir())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{Log: log, Version: "v-test", cfg: &config.Config{}}
	d.def.m = defense.NewManager(log, defense.WithEventHook(d.evidenceEvent))
	t.Cleanup(func() { d.stopEvidence(); d.def.m.Close() })
	mux := http.NewServeMux()
	d.defenseRoutes(mux)
	return d, mux
}

func evCall(t *testing.T, mux *http.ServeMux, method, path string, body any, want int) []byte {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, rd)
	r = r.WithContext(withTestPeer(r.Context()))
	mux.ServeHTTP(rec, r)
	if rec.Code != want {
		t.Fatalf("%s %s: %d %s (want %d)", method, path, rec.Code, rec.Body, want)
	}
	return rec.Body.Bytes()
}

func TestEvidenceOffWritesNothingThenOnWritesChain(t *testing.T) {
	d, mux := evDaemon(t)
	d.def.m.Configure(defense.Config{Enabled: true, Features: map[string]defense.Feature{}})
	d.def.m.Report(defense.Event{Kind: defense.KindDecoyHit, Severity: defense.SevMedium, Src: "192.0.2.7", Port: 22, Proto: "tcp"})
	if _, err := os.Stat(d.evidenceDir()); err == nil {
		t.Fatal("evidence dir exists although evidence is off")
	}
	var st evidenceStatusResp
	_ = json.Unmarshal(evCall(t, mux, "GET", "/v1/defense/evidence", nil, 200), &st)
	if st.Enabled || len(st.Cases) != 0 {
		t.Fatalf("%+v", st)
	}
	d.evidenceApply(defense.EvidenceConfig{Enabled: true}, true)
	d.def.m.SetNetwork("k", defense.ClassUnknown)
	for _, s := range []string{"192.0.2.7", "198.51.100.1", "192.0.2.7"} {
		d.def.m.Report(defense.Event{Kind: defense.KindDecoyHit, Severity: defense.SevMedium, Src: s, Port: 22, Proto: "tcp", Detail: "gw 00:00:5e:00:53:01 ssid=Cafe"})
	}
	d.def.m.Report(defense.Event{Kind: defense.KindFirstSeen, Severity: defense.SevInfo, Src: "203.0.113.9", Detail: "app=browser"})
	_ = json.Unmarshal(evCall(t, mux, "GET", "/v1/defense/evidence", nil, 200), &st)
	if !st.Enabled || !st.Status.ChainOK || st.Status.Lines < 4 {
		t.Fatalf("%+v", st)
	}
	es, _ := evidence.ReadDir(d.evidenceDir(), evidence.Filter{})
	for _, e := range es {
		if e.Kind == "first_seen" {
			t.Fatal("the user's own destinations must not be logged")
		}
		if strings.Contains(e.Detail, "00:00:5e") || strings.Contains(e.Detail, "Cafe") {
			t.Fatalf("network data in the log: %q", e.Detail)
		}
		if e.NetClass == "" {
			t.Fatal("no net class")
		}
	}
	if fi, _ := os.Stat(d.evidenceDir()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode())
	}

	// case, export, download, purge
	var cs evidence.Case
	_ = json.Unmarshal(evCall(t, mux, "POST", "/v1/defense/evidence/case", evCaseReq{Action: "create", Name: "x", Src: "192.0.2.7"}, 200), &cs)
	if cs.ID == "" || !cs.Pinned {
		t.Fatalf("%+v", cs)
	}
	evCall(t, mux, "POST", "/v1/defense/evidence/case", evCaseReq{Action: "create", Src: "nonsense"}, 400)
	evCall(t, mux, "POST", "/v1/defense/evidence/case", evCaseReq{Action: "create", Src: "203.0.113.50"}, 409)
	var res evidence.ExportResult
	_ = json.Unmarshal(evCall(t, mux, "POST", "/v1/defense/evidence/export", evExportReq{CaseID: cs.ID, AllNetworks: true}, 200), &res)
	if res.Lines != 2 || !strings.HasPrefix(res.Path, d.evidenceDir()) {
		t.Fatalf("%+v", res)
	}
	// without a network choice the export is refused; a preview writes nothing
	evCall(t, mux, "POST", "/v1/defense/evidence/export", evExportReq{CaseID: cs.ID}, 400)
	evCall(t, mux, "POST", "/v1/defense/evidence/export", evExportReq{CaseID: cs.ID, Net: "../x"}, 400)
	var pl evidence.ExportPlan
	_ = json.Unmarshal(evCall(t, mux, "POST", "/v1/defense/evidence/export", evExportReq{CaseID: cs.ID, AllNetworks: true, Preview: true, Anonymize: true}, 200), &pl)
	if pl.Lines != 2 || !pl.Anonymize || len(pl.Files) == 0 {
		t.Fatalf("plan %+v", pl)
	}
	evCall(t, mux, "GET", "/v1/defense/evidence/networks", nil, 200)
	var dl evDownload
	_ = json.Unmarshal(evCall(t, mux, "GET", "/v1/defense/evidence/download?name="+filepath.Base(res.Path), nil, 200), &dl)
	if dl.Size == 0 || len(dl.Data) != dl.Size {
		t.Fatalf("download %d", dl.Size)
	}
	for _, bad := range []string{"../chain.json", "..%2Fchain.json", "shunt-case-../../x.tar.gz", "events-x.jsonl", ""} {
		evCall(t, mux, "GET", "/v1/defense/evidence/download?name="+bad, nil, 400)
	}
	evCall(t, mux, "GET", "/v1/defense/evidence/download?name=shunt-case-nothing.tar.gz", nil, 404)
	// purge keeps the pinned case's lines, "all" removes them and the case
	evCall(t, mux, "POST", "/v1/defense/evidence/purge", evPurgeReq{}, 200)
	if es, _ := evidence.ReadDir(d.evidenceDir(), evidence.Filter{Src: "192.0.2.7"}); len(es) != 2 {
		t.Fatalf("pinned case lost lines: %d", len(es))
	}
	evCall(t, mux, "POST", "/v1/defense/evidence/purge", evPurgeReq{All: true}, 200)
	if es, _ := evidence.ReadDir(d.evidenceDir(), evidence.Filter{}); len(es) != 0 {
		t.Fatalf("purge all left %d lines", len(es))
	}
	_ = json.Unmarshal(evCall(t, mux, "GET", "/v1/defense/evidence", nil, 200), &st)
	if len(st.Cases) != 0 || !st.Status.ChainOK {
		t.Fatalf("%+v", st)
	}
	evCall(t, mux, "POST", "/v1/defense/evidence/case", evCaseReq{Action: "bogus"}, 400)
	evCall(t, mux, "GET", "/v1/defense/evidence/abuse?src=nonsense", nil, 400)
	evCall(t, mux, "GET", "/v1/defense/evidence/abuse?src=10.0.0.1", nil, 422)

	// switching off closes the log, files stay
	d.evidenceApply(defense.EvidenceConfig{}, true)
	d.def.m.Report(defense.Event{Kind: defense.KindScan, Severity: defense.SevHigh, Src: "192.0.2.99"})
	if es, _ := evidence.ReadDir(d.evidenceDir(), evidence.Filter{Src: "192.0.2.99"}); len(es) != 0 {
		t.Fatal("logged while off")
	}
}

func withTestPeer(ctx context.Context) context.Context {
	return context.WithValue(ctx, peerKey{}, &peer{uid: 0})
}

func TestEvidenceRoutesNeedAuthorization(t *testing.T) {
	_, mux := evDaemon(t)
	for _, c := range []struct{ m, p string }{
		{"POST", "/v1/defense/evidence/case"}, {"POST", "/v1/defense/evidence/purge"}, {"POST", "/v1/defense/evidence/export"}, {"GET", "/v1/defense/evidence/networks"},
		{"GET", "/v1/defense/evidence/download?name=shunt-case-a.tar.gz"}, {"GET", "/v1/defense/evidence/abuse?src=192.0.2.1"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.m, c.p, strings.NewReader("{}"))) // no peer credentials
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", c.m, c.p, rec.Code)
		}
	}
}
