package approve

import (
	"context"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/change/changetest"
	"github.com/hsouf/shipgate/internal/gittufx"
)

type fixture struct {
	e            *changetest.Env
	alice, bob   changetest.Person
	base, change string
}

// setup: alice authors feature-x on top of main; bob is the reviewer.
func setup(t *testing.T) *fixture {
	alice := changetest.NewPerson(t, "alice")
	bob := changetest.NewPerson(t, "bob")
	e := changetest.New(t, alice)
	base := e.Run("rev-parse", "main")
	c := e.Commit(alice, []string{base}, map[string]string{"app.go": "package app\n"}, "add app")
	e.Push("refs/heads/feature-x", c)
	e.UseKey(bob)
	e.Gittuf.Approver = bob
	return &fixture{e: e, alice: alice, bob: bob, base: base, change: c}
}

func (f *fixture) run() error {
	return Run(context.Background(), Options{Feature: "feature-x", Target: "main", Env: f.e.ChangeEnv()})
}

func (f *fixture) approvers(t *testing.T) []change.Signer {
	t.Helper()
	ctx := context.Background()
	c, err := change.Inspect(ctx, f.e.ChangeEnv(), "refs/heads/main", "refs/heads/feature-x")
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := change.Approvals(ctx, f.e.ChangeEnv(), c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) originHas(ref string) bool {
	return f.e.Run("ls-remote", "origin", ref) != ""
}

func TestApproveRecordsAndPushesApproval(t *testing.T) {
	f := setup(t)
	if err := f.run(); err != nil {
		t.Fatalf("approve: %v\n%s", err, f.e.Out.String())
	}
	a := f.approvers(t)
	if len(a) != 1 || a[0].Fingerprint != f.bob.FP() {
		t.Fatalf("approvers = %+v, want bob", a)
	}
	if !f.originHas(gittufx.AttestationsRef) || !f.originHas(gittufx.RSLRef) {
		t.Error("approval and RSL entry were not pushed")
	}
	if got := strings.Join(f.e.Gittuf.Calls, ","); got != "sync,authorize,apply" {
		t.Errorf("gittuf calls = %s", got)
	}
	out := f.e.Out.String()
	for _, want := range []string{"merge tree", "add app", f.alice.FP(), "voids this approval"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestApproveDeniesAuthor(t *testing.T) {
	f := setup(t)
	f.e.UseKey(f.alice)
	f.e.Gittuf.Approver = f.alice
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "different person") {
		t.Fatalf("err = %v, want author denied", err)
	}
	if len(f.approvers(t)) != 0 {
		t.Error("approval recorded for the author")
	}
}

func TestApproveDeniesUnsignedCommit(t *testing.T) {
	f := setup(t)
	unsigned := f.e.Commit(changetest.Person{}, []string{f.change}, map[string]string{"evil": "x"}, "pushed with a stolen token")
	f.e.Push("refs/heads/feature-x", unsigned)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("err = %v, want unsigned commit denied", err)
	}
	for _, c := range f.e.Gittuf.Calls {
		if c == "authorize" {
			t.Error("authorize called for a change with an unsigned commit")
		}
	}
}

func TestApproveDeniesSoftwareSigningKey(t *testing.T) {
	f := setup(t)
	f.e.Run("config", "gpg.format", "openpgp")
	if err := f.run(); err == nil {
		t.Fatal("approve succeeded without an SSH security key configured")
	}
}

func TestApproveDeniesLocalBranchDifferentFromRemote(t *testing.T) {
	f := setup(t)
	local := f.e.Commit(f.alice, []string{f.change}, map[string]string{"local": "x"}, "local only")
	f.e.Run("update-ref", "refs/heads/feature-x", local)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "differs from") {
		t.Fatalf("err = %v, want local/remote mismatch denied", err)
	}
}

func TestApproveRollsBackWhenGittufApprovesDifferentTree(t *testing.T) {
	f := setup(t)
	f.e.Gittuf.AuthorizeWrongTree = true
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "did not record a valid approval") {
		t.Fatalf("err = %v, want tree mismatch denied", err)
	}
	if v := f.e.Run("for-each-ref", gittufx.AttestationsRef); v != "" {
		t.Errorf("local attestations ref not rolled back: %s", v)
	}
	if f.originHas(gittufx.AttestationsRef) {
		t.Error("mismatched approval was pushed")
	}
}

func TestApproveIsIdempotent(t *testing.T) {
	f := setup(t)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	f.e.Gittuf.Calls = nil
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.e.Gittuf.Calls {
		if c == "authorize" {
			t.Error("approved twice")
		}
	}
}
