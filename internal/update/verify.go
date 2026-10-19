package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ReleaseSigner is the public key (ssh-ed25519, base64 blob) that signs the
// SHA256SUMS of every release; the same key as RELEASE_SIGNER in install.sh.
const ReleaseSigner = "AAAAC3NzaC1lZDI1NTE5AAAAIBKBIRHWh1Rv3SN7z8GTV6Kj6SfFkdK0GN3CNOI58HG5"

// ReleaseNamespace is the ssh-keygen -Y namespace of the signature.
const ReleaseNamespace = "shunt-release"

// VerifySums checks an `ssh-keygen -Y sign` signature (SSHSIG, ed25519) of
// sums against the release key, so a downloaded update can be trusted
// without ssh-keygen (Windows, Android).
func VerifySums(sums, sig []byte) error {
	return verifySSHSig(sums, sig, ReleaseSigner, ReleaseNamespace)
}

func verifySSHSig(msg, armored []byte, signerB64, ns string) error {
	var b64 strings.Builder
	in := false
	for _, l := range strings.Split(string(armored), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "-----BEGIN SSH SIGNATURE-----":
			in = true
		case l == "-----END SSH SIGNATURE-----":
			in = false
		case in:
			b64.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil || len(raw) < 10 || string(raw[:6]) != "SSHSIG" {
		return errors.New("not an SSH signature")
	}
	r := &wireReader{b: raw[6:]}
	if v := r.u32(); v != 1 {
		return fmt.Errorf("unknown signature version %d", v)
	}
	pub, sigNS, _, hashAlg, sigBlob := r.str(), r.str(), r.str(), r.str(), r.str()
	if r.err != nil {
		return errors.New("signature is cut off")
	}
	want, err := base64.StdEncoding.DecodeString(signerB64)
	if err != nil || !bytes.Equal(pub, want) {
		return errors.New("signed by another key")
	}
	if string(sigNS) != ns {
		return errors.New("wrong signature namespace")
	}
	var h []byte
	switch string(hashAlg) {
	case "sha512":
		s := sha512.Sum512(msg)
		h = s[:]
	case "sha256":
		s := sha256.Sum256(msg)
		h = s[:]
	default:
		return fmt.Errorf("unknown hash %q", hashAlg)
	}
	pr := &wireReader{b: pub}
	if string(pr.str()) != "ssh-ed25519" {
		return errors.New("not an ed25519 key")
	}
	key := pr.str()
	sr := &wireReader{b: sigBlob}
	if string(sr.str()) != "ssh-ed25519" {
		return errors.New("not an ed25519 signature")
	}
	sg := sr.str()
	if pr.err != nil || sr.err != nil || len(key) != ed25519.PublicKeySize || len(sg) != ed25519.SignatureSize {
		return errors.New("malformed key or signature")
	}
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{[]byte(ns), nil, hashAlg, h} {
		binary.Write(&signed, binary.BigEndian, uint32(len(f)))
		signed.Write(f)
	}
	if !ed25519.Verify(key, signed.Bytes(), sg) {
		return errors.New("signature does not match")
	}
	return nil
}

// SumFor returns the SHA-256 (hex) that a SHA256SUMS file lists for name.
func SumFor(sums []byte, name string) (string, bool) {
	for _, l := range strings.Split(string(sums), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

type wireReader struct {
	b   []byte
	err error
}

func (r *wireReader) u32() uint32 {
	if len(r.b) < 4 {
		r.err = errors.New("short")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *wireReader) str() []byte {
	n := r.u32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.err = errors.New("short")
		return nil
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s
}
