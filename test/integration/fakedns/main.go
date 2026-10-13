// Command fakedns is a test helper for the integration test.
//
//	fakedns serve -tag direct -listen 10.99.0.1:53 -a site.test=10.99.0.3
//	    TXT <any>  → "<tag> <client ip>"   (who asked, over which path)
//	    A <name>   → configured address, TTL 30
//	fakedns query [-tcp] -server 1.2.3.4:53 -type TXT whoami.test
//	    prints the answer, or the rcode (NXDOMAIN, SERVFAIL, …), or ERROR
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakedns serve|query ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "query":
		query(os.Args[2:])
	default:
		os.Exit(2)
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	tag := fs.String("tag", "dns", "tag reported in TXT answers")
	var listen, records multi
	fs.Var(&listen, "listen", "address to listen on (repeatable)")
	fs.Var(&records, "a", "name=ip A record (repeatable)")
	_ = fs.Parse(args)
	a := map[string]net.IP{}
	for _, r := range records {
		n, ip, _ := strings.Cut(r, "=")
		a[dns.Fqdn(n)] = net.ParseIP(ip)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		switch {
		case q.Qtype == dns.TypeTXT && q.Name == "o-o.myaddr.l.google.com.":
			// like Google: the address of the resolver that asked
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{host},
			})
		case q.Qtype == dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{*tag + " " + host},
			})
		case q.Qtype == dns.TypeA && a[q.Name] != nil:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   a[q.Name],
			})
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	for _, l := range listen {
		for _, n := range []string{"udp", "tcp"} {
			s := &dns.Server{Addr: l, Net: n, Handler: h}
			go func() {
				if err := s.ListenAndServe(); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			}()
		}
	}
	select {}
}

func query(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	server := fs.String("server", "127.0.0.53:53", "server")
	typ := fs.String("type", "A", "A or TXT")
	tcp := fs.Bool("tcp", false, "use TCP")
	sport := fs.Int("sport", 0, "UDP source port (0: any)")
	_ = fs.Parse(args)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fs.Arg(0)), dns.StringToType[*typ])
	c := &dns.Client{Timeout: 3 * time.Second}
	if *sport != 0 {
		c.Dialer = &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.UDPAddr{Port: *sport}}
	}
	if *tcp {
		c.Net = "tcp"
	}
	r, _, err := c.Exchange(m, *server)
	if err != nil {
		fmt.Println("ERROR")
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		fmt.Println(dns.RcodeToString[r.Rcode])
		return
	}
	var out []string
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.TXT:
			out = append(out, strings.Join(v.Txt, ""))
		case *dns.A:
			out = append(out, v.A.String())
		}
	}
	fmt.Println(strings.Join(out, " "))
}
