package clockcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func server(offset time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(offset).UTC().Format(http.TimeFormat))
	}))
}

func TestOffset(t *testing.T) {
	for _, want := range []time.Duration{0, 10 * time.Minute, -3 * time.Hour} {
		s := server(want)
		got, err := Offset(context.Background(), s.Client(), s.URL)
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if d := got - want; d > 1500*time.Millisecond || d < -1500*time.Millisecond {
			t.Errorf("offset %v, want about %v", got, want)
		}
	}
}

func TestMedianIgnoresOneLiar(t *testing.T) {
	a, b, c := server(0), server(0), server(2*time.Hour)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	got, err := Median(context.Background(), http.DefaultClient, []string{a.URL, c.URL, b.URL, "http://127.0.0.1:1/"})
	if err != nil || Skewed(got, time.Minute) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestNoDate(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil
	}))
	defer s.Close()
	if _, err := Median(context.Background(), s.Client(), []string{s.URL}); err == nil {
		t.Fatal("no Date header must be an error")
	}
}
