// Command ovpnspike tries internal/ovpndroid on a device: it starts the
// Android build of openvpn with a .ovpn file and fetches a URL through the
// tunnel's netstack. Run from adb shell (the device's own VPN must be off or
// let adb shell out directly).
//
//	ovpnspike -exe ./libopenvpn.so -config t.ovpn -url http://10.67.0.1/
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Bob-Nixkoenner/the_shunt/internal/ovpndroid"
)

func main() {
	exe := flag.String("exe", "./libopenvpn.so", "openvpn program")
	config := flag.String("config", "t.ovpn", ".ovpn file")
	url := flag.String("url", "http://10.67.0.1/", "fetched through the tunnel")
	dir := flag.String("dir", "./ovpn-work", "work folder")
	flag.Parse()
	conf, err := os.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	t, err := ovpndroid.Start(ovpndroid.Options{Exe: *exe, Config: string(conf), Dir: *dir, Logf: log.Printf})
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()
	start := time.Now()
	select {
	case <-t.Ready():
	case <-t.Done():
		log.Fatalf("openvpn ended: %v", t.Err())
	case <-time.After(30 * time.Second):
		log.Fatal("not connected after 30 s")
	}
	log.Printf("connected after %v, DNS %v", time.Since(start).Round(time.Millisecond), t.DNS())
	tn := t.Net()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tn.DialContext(ctx, network, addr)
		},
	}}
	for _, u := range []string{*url, "http://ifconfig.me/ip"} {
		r, err := hc.Get(u)
		if err != nil {
			log.Printf("GET %s: %v", u, err)
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		fmt.Printf("GET %s -> %s\n", u, b)
	}
	time.Sleep(6 * time.Second)
	rx, tx := t.Bytes()
	log.Printf("bytes rx %d tx %d", rx, tx)
}
