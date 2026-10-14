package override

import (
	"testing"
	"time"
)

func TestOverride(t *testing.T) {
	var s State
	now := time.Unix(1_800_000_000, 0)
	if r := s.Route("tunnel:a", now); r != "tunnel:a" {
		t.Fatal(r)
	}
	end := s.Pass(5*time.Minute, now)
	if r := s.Route("tunnel:a", now.Add(time.Minute)); r != "direct" || end != now.Add(5*time.Minute) {
		t.Fatalf("during pass: %s %v", r, end)
	}
	if r := s.Route("block", now.Add(time.Minute)); r != "direct" {
		t.Fatal("a pass lets blocked apps through too")
	}
	if st := s.Status(now.Add(time.Minute)); st.PassLeft != 240 {
		t.Fatalf("%+v", st)
	}
	if r := s.Route("tunnel:a", now.Add(5*time.Minute)); r != "tunnel:a" || s.Passing(now.Add(5*time.Minute)) {
		t.Fatal("pass did not end by itself")
	}
	s.Pass(5*time.Minute, now)
	s.SetPanic(true)
	if r := s.Route("tunnel:a", now); r != "block" {
		t.Fatal("panic must win over a pass")
	}
	s.SetPanic(false)
	s.Pass(0, now)
	if s.Passing(now) {
		t.Fatal("pass not ended")
	}
	if end := s.Pass(10*time.Hour, now); end != now.Add(MaxPass) {
		t.Fatalf("pass not clamped: %v", end)
	}
	if end := s.Pass(time.Second, now); end != now.Add(time.Minute) {
		t.Fatalf("pass shorter than a minute: %v", end)
	}
}
