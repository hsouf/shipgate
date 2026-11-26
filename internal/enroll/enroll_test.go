package enroll

import (
	"strings"
	"testing"
)

func TestPlanRequiresHardwareAndPIN(t *testing.T) {
	cmds, err := Plan(Options{KeyPath: "/tmp/k", Global: true})
	if err != nil {
		t.Fatal(err)
	}
	keygen := cmds[0].String()
	for _, want := range []string{"-t ed25519-sk", "-O verify-required", "write-attestation=/tmp/k.attestation"} {
		if !strings.Contains(keygen, want) {
			t.Errorf("keygen command %q missing %q", keygen, want)
		}
	}
}

func TestPlanConfiguresGitSigning(t *testing.T) {
	cmds, _ := Plan(Options{KeyPath: "/tmp/k", Global: false})
	all := ""
	for _, c := range cmds[1:] {
		all += c.String() + "\n"
	}
	for _, want := range []string{
		"git config --local gpg.format ssh",
		"git config --local user.signingkey /tmp/k.pub",
		"git config --local commit.gpgsign true",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}
