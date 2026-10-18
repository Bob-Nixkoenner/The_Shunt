//go:build !linux

package dnsproxy

import "github.com/miekg/dns"

const markUnknown = ^uint32(0)

func newUDPServer(string, dns.Handler, func()) *dns.Server { return nil }

func queryMark(dns.ResponseWriter) uint32 { return markUnknown }
