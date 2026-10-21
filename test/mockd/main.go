// Command mockd is a fake shuntd with invented data: the web UI and the
// desktop app can be run against it to take screenshots (README, store
// pages) without real tunnels, addresses or keys.
//
//	go run ./test/mockd -s /tmp/mock.sock &
//	shunt -s /tmp/mock.sock ui --no-browser --no-update-check
//
// All addresses are from the documentation ranges (RFC 5737), all keys and
// names are made up.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/api"
	"github.com/Bob-Nixkoenner/the_shunt/internal/blocklist"
	"github.com/Bob-Nixkoenner/the_shunt/internal/config"
	"github.com/Bob-Nixkoenner/the_shunt/internal/dnsproxy"
	"github.com/Bob-Nixkoenner/the_shunt/internal/health"
	"github.com/Bob-Nixkoenner/the_shunt/internal/netdetect"
	"github.com/Bob-Nixkoenner/the_shunt/internal/probe"
	"github.com/Bob-Nixkoenner/the_shunt/internal/stats"
	"github.com/Bob-Nixkoenner/the_shunt/internal/tunnel"
)

const raw = `[daemon]
socket = "/run/shunt/shuntd.sock"

[dns]
direct = "pihole"

[dns.upstream.pihole]
addr = "192.0.2.53"

[tunnel.work]
config = "/etc/shunt/tunnels/work.conf"

[tunnel.home]
config = "/etc/shunt/tunnels/home.conf"

[tunnel.nl]
config = "/etc/shunt/tunnels/nl.ovpn"
driver = "openvpn"
via = "tunnel:home"

[[network]]
name = "Home"
ssid = ["HomeWiFi"]
default_route = "tunnel:work"

[[rule]]
name = "Browser"
app = ["firefox"]
route = "tunnel:nl"

[[rule]]
name = "Mail"
app = ["thunderbird"]
route = "tunnel:work"

[[rule]]
name = "Torrent"
app = ["qbittorrent"]
route = "block"

[[rule]]
name = "Streaming direct"
domain = ["video.example.com", "cdn.example.net"]
route = "direct"

[[rule]]
name = "SSH"
port = ["tcp/22"]
route = "direct"
`

var mu sync.Mutex
var (
	panicOn bool
	passEnd time.Time
)

func main() {
	sock := flag.String("s", "/tmp/shunt-mock.sock", "socket to listen on")
	flag.Parse()
	cfg, err := config.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	_ = os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	_ = os.Chmod(*sock, 0o666)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { js(w, status(cfg)) })
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		js(w, api.ConfigView{Raw: raw, Version: "mock", Config: cfg, Tunnels: []api.TunnelConfInfo{
			{Name: "work", Type: "wireguard", Endpoint: "203.0.113.10:51820", Addresses: []string{"10.7.0.2/24"}, AllowedIPs: []string{"0.0.0.0/0"}},
			{Name: "home", Type: "wireguard", Endpoint: "198.51.100.7:51820", Addresses: []string{"10.8.0.2/24"}, AllowedIPs: []string{"0.0.0.0/0"}},
			{Name: "nl", Type: "openvpn", Endpoint: "192.0.2.80:1194", Addresses: []string{"10.9.0.6/24"}, AllowedIPs: []string{"0.0.0.0/0"}},
		}, DNSFilter: cfg.Filter()})
	})
	mux.HandleFunc("GET /v1/history", func(w http.ResponseWriter, r *http.Request) { js(w, history(r.URL.Query().Get("range"))) })
	mux.HandleFunc("POST /v1/pass", func(w http.ResponseWriter, r *http.Request) {
		var req api.PassRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		passEnd = time.Now().Add(time.Duration(req.Minutes) * time.Minute)
		if req.Minutes <= 0 {
			passEnd = time.Time{}
		}
		mu.Unlock()
		js(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/panic", func(w http.ResponseWriter, r *http.Request) {
		var req api.PanicRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		panicOn = req.On
		mu.Unlock()
		js(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/probe", func(w http.ResponseWriter, r *http.Request) {
		var req api.ProbeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ip := map[string]string{"direct": "192.0.2.201", "tunnel:work": "203.0.113.10", "tunnel:home": "198.51.100.7", "tunnel:nl": "192.0.2.80"}[req.Route]
		resolver := map[string]string{"direct": "192.0.2.53", "tunnel:work": "203.0.113.53", "tunnel:home": "198.51.100.53", "tunnel:nl": "192.0.2.153"}[req.Route]
		res := probe.Result{IP: ip, Resolver: resolver}
		if req.Route == "block" {
			res = probe.Result{IPErr: "blocked", DNSErr: "blocked"}
		}
		js(w, res)
	})
	mux.HandleFunc("GET /v1/pending", func(w http.ResponseWriter, r *http.Request) { js(w, []any{}) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { js(w, map[string]any{}) })
	log.Fatal((&http.Server{Handler: mux}).Serve(ln))
}

func js(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func status(cfg *config.Config) api.Status {
	now := time.Now()
	mu.Lock()
	pl := int64(0)
	if d := time.Until(passEnd); d > 0 {
		pl = int64(d.Seconds())
	}
	pn := panicOn
	mu.Unlock()
	peer := func(ep, key string, ago time.Duration, rx, tx int64) []tunnel.PeerStatus {
		return []tunnel.PeerStatus{{PublicKey: key, Endpoint: ep, LastHandshake: now.Add(-ago), RxBytes: rx, TxBytes: tx, KeepaliveSec: 25}}
	}
	const gb, mb = 1 << 30, 1 << 20
	sum := func(m, l, t int64) stats.Summary {
		return stats.Summary{Month: stats.Bytes{RX: m * 4 / 5, TX: m / 5}, LastMonth: stats.Bytes{RX: l * 4 / 5, TX: l / 5}, Total: stats.Bytes{RX: t * 4 / 5, TX: t / 5}, Since: now.AddDate(0, -3, 0).Unix()}
	}
	// the default lists with invented sizes
	f := cfg.Filter()
	var lists []blocklist.Status
	for i, ref := range f.Lists("paranoid") {
		var levels []string
		for _, lv := range []string{"low", "normal", "paranoid"} {
			if slices.Contains(f.Lists(lv), ref) {
				levels = append(levels, lv)
			}
		}
		lists = append(lists, blocklist.Status{Name: ref, URL: f.ListURL(ref), Levels: levels, Entries: 3000 + (i*7919)%140000, Updated: now.Add(-time.Duration(3+i%7) * time.Hour)})
	}
	rec := func(ago time.Duration, name, level, list, route string) dnsproxy.Blocked {
		return dnsproxy.Blocked{Time: now.Add(-ago), Name: name, Level: level, List: list, Route: route}
	}
	return api.Status{
		Traffic: map[string]stats.Summary{
			"work":  sum(14*gb+300*mb, 38*gb, 96*gb),
			"home":  sum(3*gb+800*mb, 9*gb, 21*gb),
			"nl":    sum(1*gb+200*mb, 2*gb, 6*gb),
			"total": sum(19*gb+300*mb, 49*gb, 123*gb),
		},
		DefaultRoute: "tunnel:work",
		Panic:        pn,
		PassLeft:     pl,
		Tunnels: []api.TunnelStatus{
			{Name: "work", Iface: "sh-work", Driver: "wireguard", Up: true, Peers: peer("203.0.113.10:51820", "mockWorkPublicKey0000000000000000000000000=", 38*time.Second, 5*gb, 1*gb),
				Health: &health.Report{State: "ok", LatencyMs: 23, HandshakeAge: 38}},
			{Name: "home", Iface: "sh-home", Driver: "wireguard", Up: true, Peers: peer("198.51.100.7:51820", "mockHomePublicKey0000000000000000000000000=", 71*time.Second, 900*mb, 200*mb),
				Health: &health.Report{State: "ok", LatencyMs: 61, HandshakeAge: 71}},
			{Name: "nl", Iface: "sh-nl", Driver: "openvpn", Up: true, Via: "tunnel:home", Peers: peer("192.0.2.80:1194", "", 12*time.Second, 400*mb, 80*mb),
				Health: &health.Report{State: "ok", LatencyMs: 94, Loss: 0.05, HandshakeAge: 12}},
		},
		Groups: []api.GroupStatus{
			{Name: "Browser", Procs: 14, Route: "tunnel:nl", Apps: []string{"firefox"}},
			{Name: "Mail", Procs: 3, Route: "tunnel:work", Apps: []string{"thunderbird"}},
			{Name: "Torrent", Procs: 0, Route: "block", Apps: []string{"qbittorrent"}},
		},
		Rules:    []string{"Browser -> tunnel:nl", "Mail -> tunnel:work", "Torrent -> block", "Streaming direct -> direct", "SSH -> direct"},
		Routes:   []string{"direct", "block", "tunnel:work", "tunnel:home", "tunnel:nl"},
		DNS:      map[string][]string{"direct": {"192.0.2.53"}, "tunnel:work": {"10.7.0.1"}, "tunnel:home": {"10.8.0.1"}, "tunnel:nl": {"10.9.0.1"}},
		Network:  "Home",
		Firewall: "off",
		Version:  "v0.7.1",
		NetInfo:  netdetect.Info{Iface: "wlan0", SSID: "HomeWiFi", GatewayIP: "192.168.1.1", GatewayMAC: "02:00:00:00:00:01"},
		DNSFilter: &api.DNSFilterStatus{
			Default: "normal",
			Routes:  map[string]string{"direct": "normal", "tunnel:work": "normal", "tunnel:home": "paranoid", "tunnel:nl": "normal"},
			Lists:   lists,
			Stats: dnsproxy.FilterStats{Blocked: 4182, ByLevel: map[string]uint64{"normal": 3790, "paranoid": 392}, Recent: []dnsproxy.Blocked{
				rec(40*time.Second, "ads.tracker.example", "normal", "easylist", "tunnel:work"),
				rec(2*time.Minute, "metrics.example.net", "normal", "easylist", "tunnel:nl"),
				rec(7*time.Minute, "pixel.shop.example", "paranoid", "crypto", "tunnel:home"),
				rec(11*time.Minute, "cdn.malware.example", "normal", "malware", "direct"),
			}},
		},
	}
}

func history(rng string) stats.History {
	now := time.Now()
	window, step := int64(24*3600), int64(300)
	switch rng {
	case "1h":
		window, step = 3600, 60
	case "7d":
		window, step = 7*24*3600, 3600
	case "30d":
		window, step = 30*24*3600, 6*3600
	}
	n := int(window / step)
	from := now.Unix()/step*step - window + step
	h := stats.History{Range: rng, From: from, Step: step, Tunnels: map[string][]int64{"work": nil, "home": nil, "nl": nil}}
	for i := 0; i < n; i++ {
		t := from + int64(i)*step
		hour := float64(t%86400) / 3600
		day := 0.5 + 0.5*math.Sin((hour-9)/24*2*math.Pi)
		wob := 0.75 + 0.2*math.Sin(float64(i)*0.31) + 0.12*math.Sin(float64(i)*0.07+1) + 0.08*math.Sin(float64(i)*1.7)
		rx := int64(day * wob * 2.2e6 * float64(step) / 300)
		tx := rx / 5
		dns := int64(day*wob*6) + 1
		h.Points = append(h.Points, stats.Point{T: t, RX: rx, TX: tx, DNS: dns})
		h.Tunnels["work"] = append(h.Tunnels["work"], (rx+tx)*6/10)
		h.Tunnels["home"] = append(h.Tunnels["home"], (rx+tx)*3/10)
		h.Tunnels["nl"] = append(h.Tunnels["nl"], (rx+tx)/10)
		h.RX, h.TX, h.DNS = h.RX+rx, h.TX+tx, h.DNS+dns
	}
	h.DNSToday, h.DNSMonth = 212, 4182
	return h
}
