package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Small honeypots: a fake telnet login (telnet.go) and a fake SSH server that
// refuses every login (ssh.go). Passwords are never kept: only their length
// and a short hash prefix.

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

// cleanField is cleanName for one value inside an event detail: spaces
// become "_", so what a visitor sends (user name, path, client version)
// cannot add fields of its own (" tool=nmap", " via=...") to the detail.
func cleanField(s string) string { return strings.ReplaceAll(cleanName(s), " ", "_") }

// PasswordDigest returns "len=N h=xxxxxxxx" (4-byte SHA-256 prefix).
func PasswordDigest(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return "len=" + itoa(len(pw)) + " h=" + hex.EncodeToString(h[:4])
}
