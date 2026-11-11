package defense

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
)

// A very small honeypot: a fake telnet login and an SSH banner trap. Real SSH
// is not implemented (x/crypto/ssh is only an indirect dependency here).
// Passwords are never kept: only their length and a short hash prefix.

const maxLine = 128

func readLine(r *bufio.Reader) (string, bool) {
	var sb strings.Builder
	for sb.Len() < maxLine {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), false
		}
		if b == '\n' {
			return strings.TrimRight(sb.String(), "\r"), true
		}
		if b == 0xff { // telnet command: skip option bytes
			_, _ = r.ReadByte()
			_, _ = r.ReadByte()
			continue
		}
		sb.WriteByte(b)
	}
	return sb.String(), true
}

// cleanName keeps printable ASCII and at most 32 characters.
func cleanName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			sb.WriteRune(r)
		}
		if sb.Len() >= 32 {
			break
		}
	}
	return sb.String()
}

// PasswordDigest returns "len=N h=xxxxxxxx" (4-byte SHA-256 prefix).
func PasswordDigest(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return "len=" + itoa(len(pw)) + " h=" + hex.EncodeToString(h[:4])
}

func telnetTrap(c net.Conn, src netip.Addr, port int, hit func(Hit)) {
	r := bufio.NewReader(c)
	for try := 0; try < 3; try++ {
		if _, err := c.Write([]byte("login: ")); err != nil {
			return
		}
		user, ok := readLine(r)
		if !ok && user == "" {
			return
		}
		if _, err := c.Write([]byte("Password: ")); err != nil {
			return
		}
		pw, ok2 := readLine(r)
		hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevMedium,
			Detail: "telnet login user=" + cleanName(user) + " " + PasswordDigest(pw)})
		if !ok2 {
			return
		}
		_, _ = c.Write([]byte("\r\nLogin incorrect\r\n"))
	}
}

func sshBannerTrap(c net.Conn, src netip.Addr, port int, hit func(Hit)) {
	if _, err := c.Write([]byte(Banner(22))); err != nil {
		return
	}
	line, _ := readLine(bufio.NewReader(c))
	if strings.HasPrefix(line, "SSH-") {
		hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevMedium, Detail: "ssh client " + cleanName(line)})
	}
}
