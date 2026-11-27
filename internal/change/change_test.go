package change

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/gitx"
	"github.com/hsouf/shipgate/internal/sshsig"
)

// TestRealGitSignature signs a commit with git and a software ed25519 key. It
// proves the payload shipgate extracts is what git signed, and that the
// production verifier still refuses a key that is not a security key.
func TestRealGitSignature(t *testing.T) {
	for _, bin := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	git := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	git("init", "-q")
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")
	git("config", "gpg.format", "ssh")
	git("config", "user.signingkey", key+".pub")
	git("commit", "-q", "-S", "--allow-empty", "-m", "signed")

	ctx := context.Background()
	g := &gitx.Repo{Dir: dir}
	raw, err := g.CatFile(ctx, "commit", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	payload, sig := gitx.SplitCommitSignature(raw)
	if sig == nil {
		t.Fatal("no signature found")
	}
	if _, err := sshsig.Verify(ctx, sig, payload, "git"); err != nil {
		t.Fatalf("payload extracted from the commit does not verify: %v", err)
	}
	_, err = HardwareVerifier{}.Verify(ctx, payload, sig, "git")
	if err == nil || !strings.Contains(err.Error(), "not a hardware security key") {
		t.Fatalf("err = %v, want software key rejected", err)
	}

	// SigningKey must also refuse a software key.
	if _, _, err := SigningKey(ctx, g); err == nil {
		t.Error("SigningKey accepted a software key")
	}
}

func TestPAE(t *testing.T) {
	// Test vector from the DSSE spec.
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Errorf("PAE = %q, want %q", got, want)
	}
}

func TestBranchRef(t *testing.T) {
	for in, want := range map[string]string{"main": "refs/heads/main", "refs/heads/feature-x": "refs/heads/feature-x"} {
		if got, err := BranchRef(in); err != nil || got != want {
			t.Errorf("BranchRef(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "refs/tags/v1", "--upload-pack=x", "refs/heads/"} {
		if _, err := BranchRef(bad); err == nil {
			t.Errorf("BranchRef(%q) accepted", bad)
		}
	}
}
