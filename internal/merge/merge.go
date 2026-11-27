// Package merge performs a local merge into a protected branch, signs it with
// the enrolled key, records the gittuf RSL entry and pushes the branch along
// with refs/gittuf/*.
//
// Why local: a merge made by the forge's button is signed by the forge, not
// by a key in the gittuf delegation graph, so it cannot satisfy policy. A
// merge bot with an HSM-held key is planned for v0.2.
//
// Order of operations, each failing closed:
//  1. sync gittuf metadata and both branches; local must match the remote;
//  2. every commit in the change is signed with touch + PIN on a security key;
//  3. a valid approval exists for the exact (target tip, merge tree) from a
//     key that signed none of the commits;
//  4. gittuf verify-mergeable accepts the merge under policy;
//  5. build the merge commit with exactly the approved tree and sign it;
//  6. record the RSL entry, run gittuf verify-ref locally;
//  7. push the branch and the RSL atomically. If the remote moved, nothing is
//     pushed and local refs are rolled back.
package merge

import (
	"context"
	"fmt"
	"strings"

	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/gittufx"
)

// CommitFunc creates a signed commit with the given tree, parents and
// message and returns its ID.
type CommitFunc func(ctx context.Context, tree string, parents []string, msg string) (string, error)

// Options controls a merge.
type Options struct {
	Feature string // branch to merge, e.g. "feature-x"
	Target  string // protected branch, e.g. "main"
	Env     change.Env
	// Commit defaults to git commit-tree -S, which signs with the enrolled
	// key (touch + PIN).
	Commit CommitFunc
}

// Run merges Feature into Target.
func Run(ctx context.Context, o Options) error {
	env := o.Env
	targetRef, err := change.BranchRef(o.Target)
	if err != nil {
		return err
	}
	featureRef, err := change.BranchRef(o.Feature)
	if err != nil {
		return err
	}
	_, key, err := change.SigningKey(ctx, env.Git)
	if err != nil {
		return err
	}
	head, err := env.Git.CurrentBranch(ctx)
	if err != nil {
		return err
	}
	checkedOut := head == targetRef
	if checkedOut {
		dirty, err := env.Git.Output(ctx, "status", "--porcelain", "--untracked-files=no")
		if err != nil {
			return err
		}
		if dirty != "" {
			return fmt.Errorf("%s is checked out with uncommitted changes; commit or stash them first", o.Target)
		}
	}

	c, err := change.Prepare(ctx, env, targetRef, featureRef)
	if err != nil {
		return err
	}

	approvers, rejected, err := change.Approvals(ctx, env, c)
	if err != nil {
		return err
	}
	independent := change.Independent(c, approvers)
	if len(independent) == 0 {
		return noApprovalError(c, approvers, rejected, o.Feature)
	}
	if err := env.Gittuf.VerifyMergeable(ctx, targetRef, featureRef); err != nil {
		return fmt.Errorf("gittuf policy does not allow this merge: %w", err)
	}

	fmt.Fprintf(env.Out, "Merging %s -> %s at tree %s\n", featureRef, targetRef, c.Tree)
	for _, a := range independent {
		fmt.Fprintf(env.Out, "  approved by %s\n", a.Fingerprint)
	}
	fmt.Fprintln(env.Out, "\nTouch your security key and enter your PIN when asked (twice: merge commit, RSL entry).")

	commit := o.Commit
	if commit == nil {
		commit = signedCommitTree(env)
	}
	msg := mergeMessage(o, c, independent)
	merged, err := commit(ctx, c.Tree, []string{c.Base, c.Tip}, msg)
	if err != nil {
		return fmt.Errorf("creating merge commit: %w", err)
	}
	signer, err := change.VerifyCommit(ctx, env, merged)
	if err != nil {
		return fmt.Errorf("merge commit: %w", err)
	}
	if signer.Fingerprint != key.Fingerprint() {
		return fmt.Errorf("merge commit was signed by %s, not your configured key %s", signer.Fingerprint, key.Fingerprint())
	}
	if tree, err := env.Git.Output(ctx, "rev-parse", merged+"^{tree}"); err != nil || tree != c.Tree {
		return fmt.Errorf("merge commit tree %q is not the approved tree %s (%v)", tree, c.Tree, err)
	}

	rslBefore, err := env.Git.RefValue(ctx, gittufx.RSLRef)
	if err != nil {
		return err
	}
	if err := moveBranch(ctx, env, targetRef, checkedOut, merged, c.Base); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var errs []string
		if err := restoreBranch(ctx, env, targetRef, checkedOut, c.Base, merged); err != nil {
			errs = append(errs, err.Error())
		}
		if err := env.Git.RestoreRef(ctx, gittufx.RSLRef, rslBefore); err != nil {
			errs = append(errs, err.Error())
		}
		if len(errs) > 0 {
			return fmt.Errorf("%w (rollback also failed: %s)", cause, strings.Join(errs, "; "))
		}
		return cause
	}

	if err := env.Gittuf.RecordLocal(ctx, targetRef); err != nil {
		return rollback(fmt.Errorf("recording RSL entry: %w", err))
	}
	if err := env.Gittuf.VerifyRef(ctx, targetRef); err != nil {
		return rollback(fmt.Errorf("gittuf verify-ref failed after merging; nothing was pushed: %w", err))
	}
	if err := env.Git.PushAtomic(ctx, env.Remote,
		targetRef+":"+targetRef,
		gittufx.RSLRef+":"+gittufx.RSLRef); err != nil {
		return rollback(fmt.Errorf("push rejected, probably because %s or the RSL moved on %s; nothing was pushed and local refs were restored. "+
			"Re-run shipgate merge; if %s moved, the approval must be renewed: %w", o.Target, env.Remote, o.Target, err))
	}

	fmt.Fprintf(env.Out, "\nmerged %s into %s as %s and pushed to %s\n", featureRef, targetRef, merged, env.Remote)
	return nil
}

func noApprovalError(c *change.Change, approvers []change.Signer, rejected []string, feature string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "no valid approval for merging %s into %s at tree %.12s", c.FeatureRef, c.TargetRef, c.Tree)
	if len(approvers) > 0 {
		b.WriteString("; the only approvals are from keys that signed commits in the change, and the approver must be a different person")
	} else {
		b.WriteString("; approvals bind to the exact tree, so any new commit, force-push or change to the target branch voids them")
	}
	if len(rejected) > 0 {
		fmt.Fprintf(&b, "; rejected signatures: %s", strings.Join(rejected, "; "))
	}
	fmt.Fprintf(&b, ". Ask a reviewer to run 'shipgate approve %s'", feature)
	return fmt.Errorf("%s", b.String())
}

func mergeMessage(o Options, c *change.Change, approvers []change.Signer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Merge branch '%s' into %s\n\n", strings.TrimPrefix(c.FeatureRef, "refs/heads/"), o.Target)
	fmt.Fprintf(&b, "Approved-tree: %s\n", c.Tree)
	for _, a := range approvers {
		fmt.Fprintf(&b, "Approved-by-key: %s\n", a.Fingerprint)
	}
	return b.String()
}

func signedCommitTree(env change.Env) CommitFunc {
	return func(ctx context.Context, tree string, parents []string, msg string) (string, error) {
		args := []string{"commit-tree", "-S", tree}
		for _, p := range parents {
			args = append(args, "-p", p)
		}
		args = append(args, "-m", msg)
		return env.Git.Interactive(ctx, args...)
	}
}

// moveBranch fast-forwards ref from old to merged. When the branch is checked
// out the working tree follows; otherwise only the ref moves.
func moveBranch(ctx context.Context, env change.Env, ref string, checkedOut bool, merged, old string) error {
	if !checkedOut {
		return env.Git.SetRef(ctx, ref, merged, old)
	}
	cur, err := env.Git.ResolveRef(ctx, ref)
	if err != nil {
		return err
	}
	if cur != old {
		return fmt.Errorf("%s moved locally during the merge", ref)
	}
	_, err = env.Git.Output(ctx, "merge", "--ff-only", "--quiet", merged)
	return err
}

func restoreBranch(ctx context.Context, env change.Env, ref string, checkedOut bool, old, merged string) error {
	if !checkedOut {
		return env.Git.SetRef(ctx, ref, old, merged)
	}
	_, err := env.Git.Output(ctx, "reset", "--keep", "--quiet", old)
	return err
}
