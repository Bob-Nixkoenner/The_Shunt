package speedtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
)

// M-Lab NDT7 (https://www.measurementlab.net/): free, no key, but M-Lab
// publishes every measurement together with the IP as open data. The UI says
// so before it is used. Download and upload run for ndt7Duration, the sizes of
// a Step do not apply. Latency is the TCP minimum RTT the server reports.
var (
	ndt7Locate   = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
	ndt7Duration = 10 * time.Second
)

func init() {
	if u := os.Getenv("SHUNT_SPEEDTEST_NDT7_LOCATE"); u != "" {
		ndt7Locate = u
	}
}

const ndt7Proto = "net.measurementlab.ndt.v7"

type ndt7Locations struct {
	Results []struct {
		Machine string            `json:"machine"`
		URLs    map[string]string `json:"urls"`
	} `json:"results"`
}

func ndt7URL(ctx context.Context, c *http.Client, key string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ndt7Locate, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("locate answered %d", resp.StatusCode)
	}
	var l ndt7Locations
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&l); err != nil {
		return "", err
	}
	for _, r := range l.Results {
		if u := r.URLs[key]; u != "" {
			return u, nil
		}
	}
	return "", errors.New("no NDT7 server offered")
}

func measureNDT7(ctx context.Context, s Step) Measurement {
	var m Measurement
	if s.Kind == KindPing {
		// NDT7 has no separate ping: the download reports the minimum RTT
		m = measureNDT7(ctx, Step{Provider: NDT7, Kind: KindDown})
		m.Mbit, m.Bytes = 0, 0
		return m
	}
	hc := client()
	defer hc.CloseIdleConnections()
	key := "wss:///ndt/v7/download"
	if s.Kind == KindUp {
		key = "wss:///ndt/v7/upload"
	}
	url, err := ndt7URL(ctx, hc, key)
	if err != nil {
		m.Err = short(err.Error())
		return m
	}
	ctx, cancel := context.WithTimeout(ctx, ndt7Duration+15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: hc, Subprotocols: []string{ndt7Proto}})
	if err != nil {
		m.Err = short(err.Error())
		return m
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 24)
	end := time.Now().Add(ndt7Duration)
	var n int64
	t0 := time.Now()
	if s.Kind == KindDown {
		rctx, rcancel := context.WithDeadline(ctx, end)
		defer rcancel()
		for {
			typ, b, err := conn.Read(rctx)
			if err != nil {
				break
			}
			if typ == websocket.MessageText {
				var v struct {
					TCPInfo struct {
						MinRTT int64 `json:"MinRTT"`
					} `json:"TCPInfo"`
				}
				if json.Unmarshal(b, &v) == nil && v.TCPInfo.MinRTT > 0 {
					m.LatencyMs = float64(v.TCPInfo.MinRTT) / 1000
				}
				continue
			}
			n += int64(len(b))
		}
	} else {
		buf := make([]byte, 1<<16)
		for time.Now().Before(end) {
			if err := conn.Write(ctx, websocket.MessageBinary, buf); err != nil {
				break
			}
			n += int64(len(buf))
		}
	}
	el := time.Since(t0)
	if n == 0 {
		m.Err = "no data moved"
		return m
	}
	m.Bytes, m.Mbit = n, mbit(n, el)
	return m
}
