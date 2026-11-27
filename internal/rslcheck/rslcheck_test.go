package rslcheck

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/change/changetest"
)

const main = "refs/heads/main"

type fakeGittuf struct {
	err   error
	calls int
	tips  []string // value of the ref when verify-ref ran
}

func (f *fakeGittuf) VerifyRef(_ context.Context, dir, ref string) error {
	f.calls++
	out, _ := exec.Command("git", "-C", dir, "rev-parse", ref).Output()
	f.tips = append(f.tips, strings.TrimSpace(string(out)))
	return f.err
}

type fixture struct {
	e              *changetest.Env
	alice, bob     changetest.Person
	m0, f1, m1, e1 string
	gittuf         *fakeGittuf
	v              *Verifier
}

// setup: main at m0 (first RSL entry); alice authors f1, bob approves,
// alice merges as m1 and records RSL entry e1.
func setup(t *testing.T) *fixture {
	alice := changetest.NewPerson(t, "alice")
	bob := changetest.NewPerson(t, "bob")
	e := changetest.New(t, alice)
	f := &fixture{e: e, alice: alice, bob: bob, gittuf: &fakeGittuf{}}
	f.m0 = e.Run("rev-parse", "main")
	e.RecordRSL(alice, main, f.m0)
	f.m1, f.e1 = f.merge(f.m0, map[string]string{"app.go": "package app\n"}, bob)
	f.v = &Verifier{Gittuf: f.gittuf, Signatures: changetest.FakeVerifier{}}
	return f
}

// merge has alice author a change on base, approved by approvers, merged and
// recorded by alice. Returns the merge commit and its RSL entry.
func (f *fixture) merge(base string, files map[string]string, approvers ...changetest.Person) (string, string) {
	e := f.e
	f.f1 = e.Commit(f.alice, []string{base}, files, "feature")
	tree := e.Run("merge-tree", "--write-tree", base, f.f1)
	if len(approvers) > 0 {
		e.WriteApproval(main, base, tree, approvers...)
	}
	m := e.CommitTree(f.alice, tree, []string{base, f.f1}, "merge")
	return m, e.RecordRSL(f.alice, main, m)
}

func (f *fixture) check(commit string) (bool, error) {
	return f.v.CommitVerifiedOnRef(context.Background(), f.e.Dir, main, commit)
}

func TestApprovedMergeIsDeployable(t *testing.T) {
	f := setup(t)
	ok, err := f.check(f.m1)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if f.gittuf.calls != 1 || f.gittuf.tips[0] != f.m1 {
		t.Errorf("verify-ref must run with main at the latest RSL entry; got %+v", f.gittuf)
	}
}

func TestDirectPushIsNotDeployable(t *testing.T) {
	f := setup(t)
	// Stolen token: a commit on the forge's main, no RSL entry, unsigned.
	evil := f.e.Commit(changetest.Person{}, []string{f.m1}, map[string]string{"evil": "x"}, "backdoor")
	f.e.Run("update-ref", main, evil)
	ok, err := f.check(evil)
	if ok || err != nil {
		t.Fatalf("ok=%v err=%v, want plain not-deployable", ok, err)
	}
	// Legitimate commits stay deployable despite the forge's main moving.
	if ok, err := f.check(f.m1); !ok || err != nil {
		t.Fatalf("legit commit after direct push: ok=%v err=%v", ok, err)
	}
}

func TestUnknownCommitIsNotDeployable(t *testing.T) {
	f := setup(t)
	if ok, err := f.check(strings.Repeat("ab", 20)); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestRecordedWithoutApprovalDenied(t *testing.T) {
	f := setup(t)
	m2, _ := f.merge(f.m1, map[string]string{"b.go": "package b\n"})
	ok, err := f.check(m2)
	if ok || err == nil || !strings.Contains(err.Error(), "no approval") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestSelfApprovedDenied(t *testing.T) {
	f := setup(t)
	m2, _ := f.merge(f.m1, map[string]string{"b.go": "package b\n"}, f.alice)
	ok, err := f.check(m2)
	if ok || err == nil || !strings.Contains(err.Error(), "signed commits in the change") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestUnsignedRSLEntryDenied(t *testing.T) {
	f := setup(t)
	f.f1 = f.e.Commit(f.alice, []string{f.m1}, map[string]string{"c": "c"}, "feature")
	tree := f.e.Run("merge-tree", "--write-tree", f.m1, f.f1)
	f.e.WriteApproval(main, f.m1, tree, f.bob)
	m2 := f.e.CommitTree(f.alice, tree, []string{f.m1, f.f1}, "merge")
	f.e.RecordRSL(changetest.Person{}, main, m2)
	ok, err := f.check(m2)
	if ok || err == nil || !strings.Contains(err.Error(), "RSL entry") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestUnsignedFeatureCommitDenied(t *testing.T) {
	f := setup(t)
	feat := f.e.Commit(changetest.Person{}, []string{f.m1}, map[string]string{"c": "c"}, "unsigned")
	tree := f.e.Run("merge-tree", "--write-tree", f.m1, feat)
	f.e.WriteApproval(main, f.m1, tree, f.bob)
	m2 := f.e.CommitTree(f.alice, tree, []string{f.m1, feat}, "merge")
	f.e.RecordRSL(f.alice, main, m2)
	ok, err := f.check(m2)
	if ok || err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestUnsignedMergeCommitDenied(t *testing.T) {
	f := setup(t)
	feat := f.e.Commit(f.alice, []string{f.m1}, map[string]string{"c": "c"}, "feature")
	tree := f.e.Run("merge-tree", "--write-tree", f.m1, feat)
	f.e.WriteApproval(main, f.m1, tree, f.bob)
	m2 := f.e.CommitTree(changetest.Person{}, tree, []string{f.m1, feat}, "merge")
	f.e.RecordRSL(f.alice, main, m2)
	ok, err := f.check(m2)
	if ok || err == nil || !strings.Contains(err.Error(), "merge commit") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestSkippedEntryNotDeployable(t *testing.T) {
	f := setup(t)
	f.e.SkipRSL(f.alice, f.e1)
	if ok, err := f.check(f.m1); ok || err != nil {
		t.Fatalf("ok=%v err=%v, want revoked entry not deployable", ok, err)
	}
}

func TestGittufFailureDenied(t *testing.T) {
	f := setup(t)
	f.gittuf.err = errors.New("threshold not met")
	ok, err := f.check(f.m1)
	if ok || err == nil || !strings.Contains(err.Error(), "verify-ref") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestFirstEntryDenied(t *testing.T) {
	f := setup(t)
	ok, err := f.check(f.m0)
	if ok || err == nil || !strings.Contains(err.Error(), "first RSL entry") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestOlderApprovedCommitStillDeployable(t *testing.T) {
	f := setup(t)
	m2, _ := f.merge(f.m1, map[string]string{"b.go": "package b\n"}, f.bob)
	for _, c := range []string{f.m1, m2} {
		if ok, err := f.check(c); !ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v", c, ok, err)
		}
	}
	if got := f.gittuf.tips[len(f.gittuf.tips)-1]; got != m2 {
		t.Errorf("verify-ref ran with main at %s, want latest entry %s", got, m2)
	}
}

func TestResultsAreCachedUntilRSLChanges(t *testing.T) {
	f := setup(t)
	f.check(f.m1)
	f.check(f.m1)
	if f.gittuf.calls != 1 {
		t.Errorf("verify-ref ran %d times, want cached", f.gittuf.calls)
	}
	f.merge(f.m1, map[string]string{"b.go": "package b\n"}, f.bob)
	f.check(f.m1)
	if f.gittuf.calls != 2 {
		t.Error("cache not invalidated by a new RSL entry")
	}
}

func TestReadLogParsesAnnotations(t *testing.T) {
	f := setup(t)
	f.e.SkipRSL(f.alice, f.e1)
	l, err := ReadLog(context.Background(), f.e.Git)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 || !l.Skipped[f.e1] || len(l.ForRef(main)) != 1 {
		t.Fatalf("log = %+v", l)
	}
}
