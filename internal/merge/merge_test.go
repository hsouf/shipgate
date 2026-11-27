package merge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/change/changetest"
	"github.com/hsouf/shipgate/internal/gittufx"
)

type fixture struct {
	e           *changetest.Env
	alice, bob  changetest.Person
	base, tip   string
	tree        string
	beforeMerge func() // runs inside the commit step, e.g. to move the remote
	signer      changetest.Person
}

// setup: alice authored feature-x and is merging it; bob approved it.
func setup(t *testing.T) *fixture {
	alice := changetest.NewPerson(t, "alice")
	bob := changetest.NewPerson(t, "bob")
	e := changetest.New(t, alice)
	base := e.Run("rev-parse", "main")
	tip := e.Commit(alice, []string{base}, map[string]string{"app.go": "package app\n"}, "add app")
	e.Push("refs/heads/feature-x", tip)
	e.UseKey(alice)
	tree := e.Run("merge-tree", "--write-tree", base, tip)
	return &fixture{e: e, alice: alice, bob: bob, base: base, tip: tip, tree: tree, signer: alice}
}

func (f *fixture) approve(by ...changetest.Person) {
	f.e.WriteApproval("refs/heads/main", f.base, f.tree, by...)
}

func (f *fixture) run() error {
	return Run(context.Background(), Options{
		Feature: "feature-x", Target: "main", Env: f.e.ChangeEnv(),
		Commit: func(_ context.Context, tree string, parents []string, msg string) (string, error) {
			if f.beforeMerge != nil {
				f.beforeMerge()
			}
			return f.e.CommitTree(f.signer, tree, parents, msg), nil
		},
	})
}

func (f *fixture) originMain() string {
	return strings.Fields(f.e.Run("ls-remote", "origin", "refs/heads/main"))[0]
}

func (f *fixture) assertNothingMerged(t *testing.T) {
	t.Helper()
	if got := f.originMain(); got != f.base {
		t.Errorf("origin main moved to %s", got)
	}
	if got := f.e.Run("rev-parse", "main"); got != f.base {
		t.Errorf("local main moved to %s", got)
	}
}

func TestMergeWithIndependentApproval(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	if err := f.run(); err != nil {
		t.Fatalf("merge: %v\n%s", err, f.e.Out.String())
	}
	merged := f.originMain()
	if got := f.e.Run("rev-parse", merged+"^{tree}"); got != f.tree {
		t.Errorf("merged tree %s, approved %s", got, f.tree)
	}
	if got := f.e.Run("rev-parse", merged+"^1", merged+"^2"); got != f.base+"\n"+f.tip {
		t.Errorf("parents = %q", got)
	}
	if f.e.Run("ls-remote", "origin", gittufx.RSLRef) == "" {
		t.Error("RSL not pushed")
	}
	if got := f.e.Run("rev-parse", "HEAD"); got != merged {
		t.Error("checked-out main did not follow the merge")
	}
	if !strings.Contains(f.e.Run("log", "-1", "--format=%B", merged), "Approved-by-key: "+f.bob.FP()) {
		t.Error("merge message does not name the approver")
	}
	if got := strings.Join(f.e.Gittuf.Calls, ","); got != "sync,verify-mergeable,record refs/heads/main,verify-ref" {
		t.Errorf("gittuf calls = %s", got)
	}
}

func TestMergeWhenTargetNotCheckedOut(t *testing.T) {
	f := setup(t)
	f.e.Run("checkout", "-q", "--detach")
	f.approve(f.bob)
	if err := f.run(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if f.e.Run("rev-parse", "main") != f.originMain() {
		t.Error("local main not updated")
	}
}

func TestMergeDeniesWithoutApproval(t *testing.T) {
	f := setup(t)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "no valid approval") {
		t.Fatalf("err = %v, want no approval", err)
	}
	f.assertNothingMerged(t)
}

func TestMergeDeniesSelfApproval(t *testing.T) {
	f := setup(t)
	f.approve(f.alice)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "different person") {
		t.Fatalf("err = %v, want self-approval denied", err)
	}
	f.assertNothingMerged(t)
}

// #11: an approval is void if the tree changes after signing.
func TestMergeDeniesStaleApprovalAfterNewCommit(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	sneaky := f.e.Commit(f.alice, []string{f.tip}, map[string]string{"app.go": "package app // changed\n"}, "after review")
	f.e.Push("refs/heads/feature-x", sneaky)
	f.e.Run("update-ref", "refs/heads/feature-x", sneaky)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "exact tree") {
		t.Fatalf("err = %v, want stale approval denied", err)
	}
	f.assertNothingMerged(t)
}

func TestMergeDeniesStaleApprovalAfterForcePush(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	rewritten := f.e.Commit(f.alice, []string{f.base}, map[string]string{"app.go": "package evil\n"}, "add app")
	f.e.Push("refs/heads/feature-x", rewritten)
	f.e.Run("update-ref", "refs/heads/feature-x", rewritten)
	if err := f.run(); err == nil {
		t.Fatal("merged after a force-push voided the approval")
	}
	f.assertNothingMerged(t)
}

func TestMergeDeniesApprovalMovedToAnotherTree(t *testing.T) {
	f := setup(t)
	other := f.e.Tree("", map[string]string{"other": "x"})
	// bob's real signature over a statement for a different tree, copied to
	// this tree's path.
	f.e.WriteApprovalClaiming("refs/heads/main", f.base, f.tree, other, f.bob)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "not this change") {
		t.Fatalf("err = %v, want mismatched statement denied", err)
	}
	f.assertNothingMerged(t)
}

func TestMergeDeniesUnsignedCommit(t *testing.T) {
	f := setup(t)
	unsigned := f.e.Commit(changetest.Person{}, []string{f.tip}, map[string]string{"evil": "x"}, "stolen token push")
	f.e.Push("refs/heads/feature-x", unsigned)
	f.e.Run("update-ref", "refs/heads/feature-x", unsigned)
	tree := f.e.Run("merge-tree", "--write-tree", f.base, unsigned)
	f.e.WriteApproval("refs/heads/main", f.base, tree, f.bob)
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("err = %v, want unsigned commit denied", err)
	}
	f.assertNothingMerged(t)
}

func TestMergeDeniesWhenPolicyRejects(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	f.e.Gittuf.VerifyMergeableErr = errors.New("bob is not an authorized principal")
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "policy does not allow") {
		t.Fatalf("err = %v, want policy deny", err)
	}
	f.assertNothingMerged(t)
}

func TestMergeRollsBackWhenVerifyRefFails(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	rslBefore := f.e.Run("for-each-ref", "--format=%(objectname)", gittufx.RSLRef)
	f.e.Gittuf.VerifyRefErr = errors.New("verification failed")
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "verify-ref failed") {
		t.Fatalf("err = %v, want verify-ref deny", err)
	}
	f.assertNothingMerged(t)
	if got := f.e.Run("for-each-ref", "--format=%(objectname)", gittufx.RSLRef); got != rslBefore {
		t.Errorf("RSL not rolled back: %q -> %q", rslBefore, got)
	}
	if f.e.Run("status", "--porcelain", "--untracked-files=no") != "" {
		t.Error("working tree left dirty after rollback")
	}
}

func TestMergeRollsBackWhenRemoteMovesMidMerge(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	f.beforeMerge = func() {
		other := f.e.Commit(f.bob, []string{f.base}, map[string]string{"x": "y"}, "someone else merged first")
		f.e.Push("refs/heads/main", other)
	}
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "nothing was pushed") {
		t.Fatalf("err = %v, want push rejected", err)
	}
	if got := f.e.Run("rev-parse", "main"); got != f.base {
		t.Errorf("local main not rolled back: %s", got)
	}
	if f.e.Run("ls-remote", "origin", gittufx.RSLRef) != "" {
		t.Error("RSL pushed even though the branch push was rejected")
	}
}

func TestMergeDeniesMergeCommitSignedByOtherKey(t *testing.T) {
	f := setup(t)
	f.approve(f.bob)
	f.signer = f.bob // configured key is alice's
	err := f.run()
	if err == nil || !strings.Contains(err.Error(), "not your configured key") {
		t.Fatalf("err = %v", err)
	}
	f.assertNothingMerged(t)
}
