// wgserver: two userspace WireGuard servers for testing the Android app in
// the emulator (the emulator reaches the host's 127.0.0.1 as 10.0.2.2).
//
// Inside each tunnel, 10.9.0.1 runs an HTTP server on :80 that answers
// "tunnel=<name>" and a DNS server on :53 that answers every A query with
// 10.9.0.1. It writes the app's settings.json (tunnels "home" and "work")
// to the directory given with -out.
//
//	go run ./test/android/wgserver -out /tmp/shunt-emu
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var serverIP = netip.MustParseAddr("10.9.0.1")

func b64(k wgtypes.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }

// loopBind is a conn.Bind with one UDP socket on a fixed address (the
// default bind listens on every address; for tests next to a real network
// the server should be reachable from this machine only).
type loopBind struct {
	ip   netip.Addr
	port int
	c    *net.UDPConn
}

func (b *loopBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.ip, uint16(b.port))))
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := c.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0], eps[0] = n, &conn.StdNetEndpoint{AddrPort: ap}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(b.port), nil
}
func (b *loopBind) Close() error {
	if b.c != nil {
		return b.c.Close()
	}
	return nil
}
func (b *loopBind) SetMark(uint32) error { return nil }
func (b *loopBind) BatchSize() int       { return 1 }
func (b *loopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return &conn.StdNetEndpoint{AddrPort: ap}, err
}
func (b *loopBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ap := ep.(*conn.StdNetEndpoint).AddrPort
	for _, buf := range bufs {
		if _, err := b.c.WriteToUDPAddrPort(buf, ap); err != nil {
			return err
		}
	}
	return nil
}

var listen = flag.String("listen", "", "listen on this address only (e.g. 127.0.0.1); default: all")

func serve(name string, port int, host string) string {
	spriv, _ := wgtypes.GeneratePrivateKey()
	cpriv, _ := wgtypes.GeneratePrivateKey()
	cpub := cpriv.PublicKey()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		log.Fatal(err)
	}
	var bind conn.Bind = conn.NewDefaultBind()
	if *listen != "" {
		bind = &loopBind{ip: netip.MustParseAddr(*listen), port: port}
	}
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelError, name+": "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", spriv[:], port, cpub[:])); err != nil {
		log.Fatal(err)
	}
	dev.Up()

	l, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s: HTTP %s %s", name, r.Method, r.URL)
		fmt.Fprintf(w, "tunnel=%s\n", name)
	}))
	pc, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 53))
	if err != nil {
		log.Fatal(err)
	}
	go dns.ActivateAndServe(nil, pc, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		for _, qq := range q.Question {
			log.Printf("%s: DNS %s", name, qq.Name)
			if qq.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(qq.Name + " 60 IN A " + serverIP.String())
				r.Answer = append(r.Answer, rr)
			}
		}
		w.WriteMsg(r)
	}))
	log.Printf("tunnel %s: udp/%d", name, port)
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		b64(cpriv), b64(spriv.PublicKey()), host, port)
}

func main() {
	out := flag.String("out", "", "write settings.json and the .conf files here")
	host := flag.String("host", "10.0.2.2", "server address as the phone sees it")
	flag.Parse()
	var tunnels []map[string]string
	for i, name := range []string{"home", "work"} {
		conf := serve(name, 51901+i, *host)
		tunnels = append(tunnels, map[string]string{"name": name, "conf": conf})
		if *out != "" {
			os.MkdirAll(*out, 0o755)
			os.WriteFile(filepath.Join(*out, name+".conf"), []byte(conf), 0o600)
		}
	}
	if *out != "" {
		// shell (adb) through "work", everything else through "home"
		b, _ := json.MarshalIndent(map[string]any{
			"tunnels": tunnels, "default": "tunnel:home",
			"apps":         map[string]string{"com.android.shell": "tunnel:work"},
			"filter_lists": []string{},
		}, "", "  ")
		os.WriteFile(filepath.Join(*out, "settings.json"), b, 0o600)
		// the same for cmd/shunt-win-proto: curl.exe through "work", the
		// rest (e.g. PowerShell, Edge) through "home"
		w, _ := json.MarshalIndent(map[string]any{
			"tunnels": tunnels, "default": "tunnel:home",
			"apps": map[string]string{`c:\windows\system32\curl.exe`: "tunnel:work"},
		}, "", "  ")
		os.WriteFile(filepath.Join(*out, "windows.json"), w, 0o600)
		log.Printf("wrote %s", *out)
	}
	select {}
}
