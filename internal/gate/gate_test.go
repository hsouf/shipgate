package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/hsouf/shipgate/internal/provenance"
)

type fakeProv struct{ src provenance.Source }

func (f fakeProv) Verify(context.Context, string) (provenance.Source, error) { return f.src, nil }

type fakeMirror struct{}

func (fakeMirror) Sync(context.Context, string) (string, error) { return "/mirror/repo", nil }

type fakePolicy struct {
	ok  bool
	err error
}

func (f fakePolicy) CommitVerifiedOnRef(context.Context, string, string, string) (bool, error) {
	return f.ok, f.err
}

const img = "registry.example/app@sha256:abc"

func TestDefaultsFailClosed(t *testing.T) {
	d := NewVerifier(Config{}).Verify(context.Background(), Request{Image: img})
	if d.Allowed {
		t.Fatal("default verifier must deny until real implementations are wired in")
	}
}

func TestTagOnlyImageDenied(t *testing.T) {
	d := NewVerifier(Config{}).Verify(context.Background(), Request{Image: "app:latest"})
	if d.Allowed || d.Checks[0].Name != "digest" {
		t.Fatalf("expected digest deny, got %+v", d)
	}
}

func TestVerifiedCommitAllowed(t *testing.T) {
	v := NewVerifier(Config{
		Provenance: fakeProv{provenance.Source{Repo: "github.com/acme/app", Commit: "c0ffee", Builder: "trusted"}},
		Mirror:     fakeMirror{},
		Policy:     fakePolicy{ok: true},
	})
	d := v.Verify(context.Background(), Request{Image: img})
	if !d.Allowed || d.Commit != "c0ffee" {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestUnverifiedCommitDenied(t *testing.T) {
	v := NewVerifier(Config{
		Provenance: fakeProv{provenance.Source{Repo: "github.com/acme/app", Commit: "bad"}},
		Mirror:     fakeMirror{},
		Policy:     fakePolicy{ok: false},
	})
	if d := v.Verify(context.Background(), Request{Image: img}); d.Allowed {
		t.Fatal("commit pushed with only a token must be denied")
	}
}

func TestPolicyErrorDenied(t *testing.T) {
	v := NewVerifier(Config{
		Provenance: fakeProv{provenance.Source{Commit: "x"}},
		Mirror:     fakeMirror{},
		Policy:     fakePolicy{err: errors.New("rsl broken")},
	})
	if d := v.Verify(context.Background(), Request{Image: img}); d.Allowed {
		t.Fatal("policy errors must fail closed")
	}
}
