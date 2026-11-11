package defense

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strings"
)

// Telnet (RFC 854/855/857/858): the trap announces WILL ECHO and WILL
// SUPPRESS-GO-AHEAD, answers other option requests with refusals, and hands
// the login logic clean input without any control bytes.

const (
	tIAC  = 255
	tDONT = 254
	tDO   = 253
	tWONT = 252
	tWILL = 251
	tSB   = 250
	tSE   = 240

	optEcho = 1
	optSGA  = 3

	maxLine = 128
)

// telnetIO reads lines with all IAC sequences removed and answers option
// negotiation on w.
type telnetIO struct {
	r      *bufio.Reader
	w      io.Writer
	skipLF bool // the byte after CR (LF or NUL) is part of the line end
}

func newTelnetIO(r io.Reader, w io.Writer) *telnetIO {
	return &telnetIO{r: bufio.NewReader(r), w: w}
}

// announce sends the server's own options.
func (t *telnetIO) announce() error {
	_, err := t.w.Write([]byte{tIAC, tWILL, optEcho, tIAC, tWILL, optSGA})
	return err
}

// readLine returns the next line (at most maxLine bytes kept; the rest of a
// long line is dropped). ok is false when the stream ended first.
func (t *telnetIO) readLine() (string, bool) {
	var sb strings.Builder
	for {
		b, err := t.r.ReadByte()
		if err != nil {
			return sb.String(), false
		}
		if t.skipLF {
			t.skipLF = false
			if b == '\n' || b == 0 {
				continue
			}
		}
		switch b {
		case tIAC:
			if lit := t.command(); lit {
				if sb.Len() < maxLine {
					sb.WriteByte(tIAC)
				}
			}
		case '\r':
			t.skipLF = true
			return sb.String(), true
		case '\n':
			return sb.String(), true
		case 0:
			// NUL padding outside a line end: ignore
		case 8, 127: // backspace / delete
			if s := sb.String(); s != "" {
				sb.Reset()
				sb.WriteString(s[:len(s)-1])
			}
		default:
			if sb.Len() < maxLine {
				sb.WriteByte(b)
			}
		}
	}
}

// command handles what follows an IAC byte. It reports true for IAC IAC (a
// literal 255 data byte).
func (t *telnetIO) command() bool {
	c, err := t.r.ReadByte()
	if err != nil {
		return false
	}
	switch c {
	case tIAC:
		return true
	case tDO, tDONT, tWILL, tWONT:
		o, err := t.r.ReadByte()
		if err != nil {
			return false
		}
		t.negotiate(c, o)
	case tSB: // skip to IAC SE
		prev := byte(0)
		for n := 0; n < 512; n++ {
			b, err := t.r.ReadByte()
			if err != nil || (prev == tIAC && b == tSE) {
				return false
			}
			if prev == tIAC && b == tIAC { // escaped 255 inside the block
				b = 0
			}
			prev = b
		}
	}
	return false
}

// negotiate answers a request. DO/DONT for our own options need no answer;
// everything else is refused (never answering a refusal, so no loops).
func (t *telnetIO) negotiate(cmd, opt byte) {
	switch cmd {
	case tDO:
		if opt != optEcho && opt != optSGA {
			_, _ = t.w.Write([]byte{tIAC, tWONT, opt})
		}
	case tWILL:
		if opt != optSGA { // the client may suppress go-ahead as well
			_, _ = t.w.Write([]byte{tIAC, tDONT, opt})
		}
	}
}

func telnetTrap(c net.Conn, src netip.Addr, port int, hit func(Hit)) {
	t := newTelnetIO(c, c)
	if t.announce() != nil {
		return
	}
	for try := 0; try < 3; try++ {
		if _, err := c.Write([]byte("login: ")); err != nil {
			return
		}
		user, ok := t.readLine()
		if !ok && user == "" {
			return
		}
		if _, err := c.Write([]byte("\r\nPassword: ")); err != nil {
			return
		}
		pw, ok2 := t.readLine()
		hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevMedium,
			Detail: "telnet login user=" + cleanName(user) + " " + PasswordDigest(pw)})
		if !ok2 {
			return
		}
		_, _ = c.Write([]byte("\r\nLogin incorrect\r\n"))
	}
}
