package speedtest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestNDT7(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/locate", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws" + strings.TrimPrefix(srv.URL, "http")
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"machine": "x", "urls": map[string]string{
			"wss:///ndt/v7/download": ws + "/ndt/v7/download", "wss:///ndt/v7/upload": ws + "/ndt/v7/upload"}}}})
	})
	mux.HandleFunc("/ndt/v7/download", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{ndt7Proto}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		c.Write(ctx, websocket.MessageText, []byte(`{"TCPInfo":{"MinRTT":12000}}`))
		buf := make([]byte, 1<<15)
		for i := 0; i < 200; i++ {
			if c.Write(ctx, websocket.MessageBinary, buf) != nil {
				return
			}
		}
		c.Close(websocket.StatusNormalClosure, "")
	})
	mux.HandleFunc("/ndt/v7/upload", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{ndt7Proto}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(1 << 24)
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	oldL, oldD := ndt7Locate, ndt7Duration
	ndt7Locate, ndt7Duration = srv.URL+"/locate", 400*time.Millisecond
	defer func() { ndt7Locate, ndt7Duration = oldL, oldD }()

	m := Measure(context.Background(), Step{Provider: NDT7, Kind: KindDown})
	if m.Err != "" || m.Mbit <= 0 || m.LatencyMs != 12 {
		t.Errorf("down: %+v", m)
	}
	m = Measure(context.Background(), Step{Provider: NDT7, Kind: KindUp})
	if m.Err != "" || m.Mbit <= 0 {
		t.Errorf("up: %+v", m)
	}
	m = Measure(context.Background(), Step{Provider: NDT7, Kind: KindPing})
	if m.Err != "" || m.LatencyMs != 12 || m.Mbit != 0 {
		t.Errorf("ping: %+v", m)
	}
	ndt7Locate = srv.URL + "/nothing"
	if m := Measure(context.Background(), Step{Provider: NDT7, Kind: KindDown}); m.Err == "" {
		t.Error("missing locate not an error")
	}
}
