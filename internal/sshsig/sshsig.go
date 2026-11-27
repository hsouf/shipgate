// Package sshsig parses OpenSSH signatures (PROTOCOL.sshsig) and public keys
// so shipgate can tell who signed something and whether the security key
// asserted a physical touch (user presence) and a PIN (user verification).
//
// Parsing alone proves nothing: the flags are only meaningful once the
// signature has been cryptographically verified, which Verify does by calling
// ssh-keygen. Callers must use Verify, not Parse, before trusting a result.
//
// Why shipgate checks the flags itself: gittuf (v0.18) verifies SSH signatures
// with golang.org/x/crypto/ssh, which checks the signature but does not
// require the user-presence or user-verification flags. See spike #3.
package sshsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	armorStart = "-----BEGIN SSH SIGNATURE-----"
	armorEnd   = "-----END SSH SIGNATURE-----"
	magic      = "SSHSIG"

	// FlagUserPresence is set when the authenticator saw a physical touch.
	FlagUserPresence byte = 0x01
	// FlagUserVerification is set when the authenticator verified a PIN or
	// biometric.
	FlagUserVerification byte = 0x04
)

// Security-key public key types.
const (
	TypeSKEd25519 = "sk-ssh-ed25519@openssh.com"
	TypeSKECDSA   = "sk-ecdsa-sha2-nistp256@openssh.com"
)

// IsSecurityKeyType reports whether keyType is a FIDO2 security-key type.
func IsSecurityKeyType(keyType string) bool {
	return keyType == TypeSKEd25519 || keyType == TypeSKECDSA
}

// PublicKey is an SSH public key in wire format.
type PublicKey struct {
	Type string
	Blob []byte
}

// Fingerprint returns the OpenSSH SHA256 fingerprint ("SHA256:...").
func (k PublicKey) Fingerprint() string {
	sum := sha256.Sum256(k.Blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ParsePublicKey parses the wire-format blob of a public key.
func ParsePublicKey(blob []byte) (PublicKey, error) {
	keyType, _, err := readString(blob)
	if err != nil {
		return PublicKey{}, fmt.Errorf("public key: %w", err)
	}
	return PublicKey{Type: string(keyType), Blob: blob}, nil
}

// ParseAuthorizedKey parses one line in authorized_keys / .pub format:
// "<type> <base64> [comment]".
func ParseAuthorizedKey(line []byte) (PublicKey, error) {
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return PublicKey{}, errors.New("public key: expected \"<type> <base64> [comment]\"")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return PublicKey{}, fmt.Errorf("public key: %w", err)
	}
	k, err := ParsePublicKey(blob)
	if err != nil {
		return PublicKey{}, err
	}
	if k.Type != fields[0] {
		return PublicKey{}, fmt.Errorf("public key: declared type %q does not match encoded type %q", fields[0], k.Type)
	}
	return k, nil
}

// Signature is a parsed SSHSIG.
type Signature struct {
	PublicKey PublicKey
	Namespace string
	HashAlg   string
	SigType   string
	// Flags and Counter are only present for security-key signatures.
	Flags   byte
	Counter uint32
}

// IsSecurityKey reports whether the signature was made by a FIDO2 key.
func (s *Signature) IsSecurityKey() bool { return IsSecurityKeyType(s.PublicKey.Type) }

// UserPresent reports whether the authenticator asserted a physical touch.
func (s *Signature) UserPresent() bool { return s.IsSecurityKey() && s.Flags&FlagUserPresence != 0 }

// UserVerified reports whether the authenticator asserted PIN verification.
func (s *Signature) UserVerified() bool {
	return s.IsSecurityKey() && s.Flags&FlagUserVerification != 0
}

// Parse decodes an armored SSH signature. It does not verify it.
func Parse(armored []byte) (*Signature, error) {
	text := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(text, armorStart) || !strings.HasSuffix(text, armorEnd) {
		return nil, errors.New("sshsig: not an armored SSH signature")
	}
	body := strings.Join(strings.Fields(text[len(armorStart):len(text)-len(armorEnd)]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	return parseBlob(raw)
}

func parseBlob(raw []byte) (*Signature, error) {
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, errors.New("sshsig: missing SSHSIG preamble")
	}
	rest := raw[len(magic):]
	if len(rest) < 4 {
		return nil, errors.New("sshsig: truncated")
	}
	if v := binary.BigEndian.Uint32(rest); v != 1 {
		return nil, fmt.Errorf("sshsig: unsupported version %d", v)
	}
	rest = rest[4:]

	var fields [5][]byte
	for i := range fields {
		var err error
		if fields[i], rest, err = readString(rest); err != nil {
			return nil, fmt.Errorf("sshsig: %w", err)
		}
	}
	if len(rest) != 0 {
		return nil, errors.New("sshsig: trailing data")
	}
	pub, err := ParsePublicKey(fields[0])
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	s := &Signature{PublicKey: pub, Namespace: string(fields[1]), HashAlg: string(fields[3])}

	sigType, sigRest, err := readString(fields[4])
	if err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	s.SigType = string(sigType)
	if _, sigRest, err = readString(sigRest); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	if IsSecurityKeyType(pub.Type) {
		if s.SigType != pub.Type {
			return nil, fmt.Errorf("sshsig: signature type %q does not match key type %q", s.SigType, pub.Type)
		}
		if len(sigRest) != 5 {
			return nil, errors.New("sshsig: security-key signature missing flags and counter")
		}
		s.Flags = sigRest[0]
		s.Counter = binary.BigEndian.Uint32(sigRest[1:])
	} else if len(sigRest) != 0 {
		return nil, errors.New("sshsig: trailing signature data")
	}
	return s, nil
}

func readString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated length")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errors.New("truncated string")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// Verify cryptographically checks that armored is a valid signature over
// message in namespace, made by the public key embedded in the signature, and
// returns the parsed signature. It does not decide whether that key is
// trusted; callers compare the fingerprint against enrolled keys or rely on
// gittuf policy for that.
func Verify(ctx context.Context, armored, message []byte, namespace string) (*Signature, error) {
	sig, err := Parse(armored)
	if err != nil {
		return nil, err
	}
	if sig.Namespace != namespace {
		return nil, fmt.Errorf("sshsig: namespace %q, want %q", sig.Namespace, namespace)
	}
	f, err := os.CreateTemp("", "shipgate-sig-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(armored); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-Y", "check-novalidate", "-n", namespace, "-s", f.Name())
	cmd.Stdin = bytes.NewReader(message)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sshsig: signature does not verify: %s", strings.TrimSpace(string(out)))
	}
	return sig, nil
}
