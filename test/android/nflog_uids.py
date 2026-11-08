#!/usr/bin/env python3
"""nflog_uids.py <pcap> : print time, UID and packet summary of an NFLOG pcap (link type 239)."""
import struct, sys
f = open(sys.argv[1], 'rb').read()
magic = f[:4]
le = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
e = '<' if le else '>'
nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
pos = 24
while pos + 16 <= len(f):
    ts, tu, cap, _ = struct.unpack(e + 'IIII', f[pos:pos + 16]); pos += 16
    d = f[pos:pos + cap]; pos += cap
    p = 4; uid = None; pay = b''
    while p + 4 <= len(d):
        ln, ty = struct.unpack('<HH', d[p:p + 4]); ty &= 0x7fff
        if ln < 4: break
        v = d[p + 4:p + ln]
        if ty == 11: uid = struct.unpack('>I', v[:4])[0]
        if ty == 9: pay = v
        p += (ln + 3) & ~3
    t = ts + tu / (1e9 if nano else 1e6)
    if pay and pay[0] >> 4 == 4:
        proto = pay[9]; src = '.'.join(map(str, pay[12:16])); dst = '.'.join(map(str, pay[16:20]))
        ihl = (pay[0] & 15) * 4
        ports = struct.unpack('>HH', pay[ihl:ihl + 4]) if proto in (6, 17) else ('', '')
        print(f'{t:.3f} uid={uid} proto={proto} {src}:{ports[0]} > {dst}:{ports[1]}')
    else:
        print(f'{t:.3f} uid={uid} v6/other')
