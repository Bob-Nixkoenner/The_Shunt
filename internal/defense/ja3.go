package defense

import (
	"crypto/md5" //nolint:gosec // JA3 is defined as an MD5 over the string; not used for security
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 follows the Salesforce specification (BSD-3-Clause, checked
// 2026-11-11): "SSLVersion,Cipher,SSLExtension,EllipticCurve,
// EllipticCurvePointFormat", decimal values joined by '-', GREASE values
// (RFC 8701) left out, MD5 of the string. JA4+ is NOT used (licence).

// isGrease reports RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa).
func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// JA3 parses a TLS record holding a ClientHello and returns the JA3 string
// and its MD5 hex digest. ok is false for anything else or a cut-off hello.
func JA3(rec []byte) (str, hash string, ok bool) {
	// record header: type 22, version, length
	if len(rec) < 9 || rec[0] != 22 {
		return
	}
	body := rec[5:]
	if n := int(binary.BigEndian.Uint16(rec[3:5])); n < len(body) {
		body = body[:n]
	}
	// handshake header: type 1 (ClientHello), 3-byte length. The record
	// length comes from the peer and can be smaller than what was read.
	if len(body) < 4 || body[0] != 1 {
		return
	}
	hl := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if hl < len(body) {
		body = body[:hl]
	}
	r := reader{b: body}
	ver, ok1 := r.u16()
	if !ok1 || !r.skip(32) { // random
		return
	}
	sid, ok1 := r.u8()
	if !ok1 || !r.skip(int(sid)) {
		return
	}
	cl, ok1 := r.u16()
	cs, ok2 := r.take(int(cl))
	if !ok1 || !ok2 || cl%2 != 0 {
		return
	}
	cm, ok1 := r.u8()
	if !ok1 || !r.skip(int(cm)) {
		return
	}
	var ciphers, exts, curves, points []string
	for i := 0; i+1 < len(cs); i += 2 {
		if v := binary.BigEndian.Uint16(cs[i:]); !isGrease(v) {
			ciphers = append(ciphers, strconv.Itoa(int(v)))
		}
	}
	if el, has := r.u16(); has {
		eb, okE := r.take(int(el))
		if !okE {
			return
		}
		er := reader{b: eb}
		for {
			t, o1 := er.u16()
			l, o2 := er.u16()
			if !o1 || !o2 {
				break
			}
			d, o3 := er.take(int(l))
			if !o3 {
				return
			}
			if isGrease(t) {
				continue
			}
			exts = append(exts, strconv.Itoa(int(t)))
			switch t {
			case 10: // supported_groups: u16 list length, u16 groups
				if len(d) >= 2 {
					for i := 2; i+1 < len(d); i += 2 {
						if v := binary.BigEndian.Uint16(d[i:]); !isGrease(v) {
							curves = append(curves, strconv.Itoa(int(v)))
						}
					}
				}
			case 11: // ec_point_formats: u8 list length, u8 formats
				if len(d) >= 1 {
					for _, b := range d[1:] {
						points = append(points, strconv.Itoa(int(b)))
					}
				}
			}
		}
	}
	str = strconv.Itoa(int(ver)) + "," + strings.Join(ciphers, "-") + "," + strings.Join(exts, "-") + "," +
		strings.Join(curves, "-") + "," + strings.Join(points, "-")
	sum := md5.Sum([]byte(str)) //nolint:gosec
	return str, hex.EncodeToString(sum[:]), true
}

type reader struct {
	b []byte
	i int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, false
	}
	s := r.b[r.i : r.i+n]
	r.i += n
	return s, true
}
func (r *reader) skip(n int) bool { _, ok := r.take(n); return ok }
func (r *reader) u8() (byte, bool) {
	s, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return s[0], true
}
func (r *reader) u16() (uint16, bool) {
	s, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(s), true
}
