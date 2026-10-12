package appwatch

import (
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
)

func TestParseExecEvents(t *testing.T) {
	ne := binary.NativeEndian
	msg := func(what uint32, tgid uint32) []byte {
		b := make([]byte, nlmsgHdrLen+cnMsgLen+16+8)
		ne.PutUint32(b[0:], uint32(len(b)))
		ne.PutUint32(b[nlmsgHdrLen:], cnIdxProc)
		ev := b[nlmsgHdrLen+cnMsgLen:]
		ne.PutUint32(ev[0:], what)
		ne.PutUint32(ev[16:], tgid+1) // pid (thread)
		ne.PutUint32(ev[20:], tgid)
		return b
	}
	in := append(msg(procEventExec, 4242), msg(0x1 /* fork */, 7)...)
	in = append(in, msg(procEventExec, 99)...)
	got := parseExecEvents(in)
	if len(got) != 2 || got[0] != 4242 || got[1] != 99 {
		t.Fatalf("got %v", got)
	}
}

func TestMatch(t *testing.T) {
	sel := func(s string) []config.AppSel {
		a, err := config.ParseAppSel(s)
		if err != nil {
			t.Fatal(err)
		}
		return []config.AppSel{a}
	}
	ff := procInfo{comm: "firefox-esr", exe: "/usr/lib/firefox-esr/firefox-esr", cgroup: "user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope"}
	qb := procInfo{comm: "qbittorrent", exe: "/app/bin/qbittorrent", cgroup: "user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.qbittorrent.qBittorrent-1234.scope"}
	long := procInfo{comm: "verylongprogram", exe: "/opt/verylongprogramname"}
	for _, c := range []struct {
		sel  string
		p    procInfo
		want bool
	}{
		{"firefox-esr", ff, true},
		{"firefox", ff, false},
		{"exe:/usr/lib/firefox-esr/firefox-esr", ff, true},
		{"flatpak:org.qbittorrent.qBittorrent", qb, true},
		{"flatpak:org.qbittorrent", qb, false},
		{"verylongprogramname", long, true}, // via exe basename
	} {
		if got := matchAny(sel(c.sel), c.p); got != c.want {
			t.Errorf("%s vs %s: got %v", c.sel, c.p.comm, got)
		}
	}
}

type fakeMover struct{ moved map[int]string }

func (f *fakeMover) Move(rel string, pid int) error { f.moved[pid] = rel; return nil }

func TestCheckSkipsPlacedProcesses(t *testing.T) {
	proc := t.TempDir()
	mk := func(pid int, comm, cg string) {
		d := filepath.Join(proc, strconv.Itoa(pid))
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "cgroup"), []byte("0::/"+cg+"\n"), 0o644)
		_ = os.Symlink("/usr/bin/"+comm, filepath.Join(d, "exe"))
	}
	mk(10, "curl", "user.slice/x.scope")
	mk(11, "curl", "shunt/apps/via/direct") // started with shunt run: keep
	mk(12, "wget", "user.slice/x.scope")
	m := &fakeMover{moved: map[int]string{}}
	w := &Watcher{Log: slog.New(slog.DiscardHandler), Mover: m, Proc: proc}
	w.SetTargets([]Target{{Name: "curl", Sels: []config.AppSel{{Kind: "name", Value: "curl"}}, Path: "shunt/apps/app/r1"}}, "shunt")
	if len(m.moved) != 1 || m.moved[10] != "shunt/apps/app/r1" {
		t.Fatalf("moved %v", m.moved)
	}
}

// Needs root in the initial network namespace: SHUNT_LIVE=1 go test -run Live
func TestConnectorLive(t *testing.T) {
	if os.Getenv("SHUNT_LIVE") == "" {
		t.Skip("set SHUNT_LIVE=1 (root) to test the real process connector")
	}
	ch, err := listenExec()
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.StartProcess("/bin/sleep", []string{"sleep", "0.2"}, &os.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Wait()
	for pid := range ch {
		if pid == p.Pid {
			return
		}
	}
	t.Fatal("exec event not seen")
}
