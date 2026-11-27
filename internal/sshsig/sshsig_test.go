package sshsig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func str(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func skPub() []byte {
	return cat(str([]byte(TypeSKEd25519)), str(bytes.Repeat([]byte{7}, 32)), str([]byte("ssh:")))
}

func armor(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(armorStart + "\n")
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n" + armorEnd + "\n")
	return []byte(b.String())
}

func skSig(pub []byte, sigType string, tail []byte) []byte {
	inner := cat(str([]byte(sigType)), str(bytes.Repeat([]byte{1}, 64)), tail)
	return armor(cat([]byte(magic), binary.BigEndian.AppendUint32(nil, 1),
		str(pub), str([]byte("git")), str(nil), str([]byte("sha512")), str(inner)))
}

func TestParseSecurityKeyFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flags  byte
		up, uv bool
	}{
		{"touch and PIN", FlagUserPresence | FlagUserVerification, true, true},
		{"touch only", FlagUserPresence, true, false},
		{"no-touch-required key", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(skSig(skPub(), TypeSKEd25519, []byte{tc.flags, 0, 0, 0, 9}))
			if err != nil {
				t.Fatal(err)
			}
			if !s.IsSecurityKey() || s.UserPresent() != tc.up || s.UserVerified() != tc.uv {
				t.Errorf("got sk=%v up=%v uv=%v", s.IsSecurityKey(), s.UserPresent(), s.UserVerified())
			}
			if s.Counter != 9 || s.Namespace != "git" {
				t.Errorf("counter=%d namespace=%q", s.Counter, s.Namespace)
			}
			if s.PublicKey.Fingerprint() != (PublicKey{Blob: skPub()}).Fingerprint() {
				t.Error("fingerprint mismatch")
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for name, in := range map[string][]byte{
		"not armored":          []byte("hello"),
		"sk sig without flags": skSig(skPub(), TypeSKEd25519, nil),
		"sk sig type mismatch": skSig(skPub(), "ssh-ed25519", []byte{5, 0, 0, 0, 1}),
		"bad preamble":         armor([]byte("NOTSIG\x00\x00\x00\x01")),
		"truncated":            armor([]byte("SSHSIG\x00\x00\x00\x01\x00\x00\x00\xff")),
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	line := TypeSKEd25519 + " " + base64.StdEncoding.EncodeToString(skPub()) + " alice@example.com\n"
	k, err := ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if k.Type != TypeSKEd25519 || !IsSecurityKeyType(k.Type) {
		t.Errorf("type %q", k.Type)
	}
	lying := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(skPub())
	if _, err := ParseAuthorizedKey([]byte(lying)); err == nil {
		t.Error("expected error when declared type differs from encoded type")
	}
}

// TestVerifyWithSoftwareKey uses a plain ed25519 key: it proves Verify checks
// the cryptography, and that such a signature is not a security-key one.
func TestVerifyWithSoftwareKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v: %s", err, out)
	}
	msg := []byte("tree abc\n\nhello\n")
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "git", "-f", key)
	cmd.Stdin = bytes.NewReader(msg)
	armored, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s, err := Verify(ctx, armored, msg, "git")
	if err != nil {
		t.Fatal(err)
	}
	pubLine, _ := os.ReadFile(key + ".pub")
	pub, err := ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	if s.PublicKey.Fingerprint() != pub.Fingerprint() {
		t.Error("fingerprint does not match signing key")
	}
	if s.IsSecurityKey() || s.UserPresent() || s.UserVerified() {
		t.Error("software key must not count as a security key")
	}

	if _, err := Verify(ctx, armored, []byte("tampered"), "git"); err == nil {
		t.Error("tampered message verified")
	}
	if _, err := Verify(ctx, armored, msg, "file"); err == nil {
		t.Error("wrong namespace verified")
	}
}
