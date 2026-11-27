// Package approve creates hardware-signed approval attestations bound to the
// exact tree being approved.
//
// Rules:
//   - the approver must be an enrolled person different from the author;
//   - the approval binds to the from/to tree, so any later change voids it (#11);
//   - approvals sourced from the forge (e.g. GitHub PR reviews) are NOT
//     sufficient on their own, because they inherit the forge's trust.
//
// The approval is a gittuf reference authorization, signed with the
// approver's security key and pushed to refs/gittuf/attestations. gittuf
// policy decides who counts as enrolled; shipgate additionally refuses an
// approval from a key that signed any commit in the change, and checks that
// gittuf recorded the approval for the exact tree the reviewer was shown.
package approve

import (
	"context"
	"fmt"

	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/gittufx"
)

// Options controls an approval.
type Options struct {
	Feature string // branch to approve, e.g. "feature-x"
	Target  string // branch it will merge into, e.g. "main"
	Env     change.Env
}

// Run approves merging Feature into Target.
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
	keyPath, key, err := change.SigningKey(ctx, env.Git)
	if err != nil {
		return err
	}
	me := key.Fingerprint()

	c, err := change.Prepare(ctx, env, targetRef, featureRef)
	if err != nil {
		return err
	}
	if c.Authors()[me] {
		return fmt.Errorf("you signed commits in %s with this key; the approval must come from a different person", featureRef)
	}

	existing, _, err := change.Approvals(ctx, env, c)
	if err != nil {
		return err
	}
	for _, a := range existing {
		if a.Fingerprint == me {
			fmt.Fprintf(env.Out, "already approved: %s -> %s at tree %s\n", featureRef, targetRef, c.Tree)
			return nil
		}
	}

	if err := printSummary(ctx, env, c, me); err != nil {
		return err
	}

	attBefore, err := env.Git.RefValue(ctx, gittufx.AttestationsRef)
	if err != nil {
		return err
	}
	rslBefore, err := env.Git.RefValue(ctx, gittufx.RSLRef)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		errAtt := env.Git.RestoreRef(ctx, gittufx.AttestationsRef, attBefore)
		errRSL := env.Git.RestoreRef(ctx, gittufx.RSLRef, rslBefore)
		if errAtt != nil || errRSL != nil {
			return fmt.Errorf("%w (rollback of local gittuf refs also failed: %v %v)", cause, errAtt, errRSL)
		}
		return cause
	}

	fmt.Fprintln(env.Out, "\nTouch your security key and enter your PIN when asked (up to 3 times: approval, attestation commit, RSL entry).")
	if err := env.Gittuf.Authorize(ctx, keyPath, targetRef, featureRef); err != nil {
		return rollback(fmt.Errorf("creating approval: %w", err))
	}

	// gittuf computes the approved tree from its RSL, not from the commits we
	// showed. Make sure they agree before anything leaves this machine.
	after, rejected, err := change.Approvals(ctx, env, c)
	if err != nil {
		return rollback(err)
	}
	found := false
	for _, a := range after {
		found = found || a.Fingerprint == me
	}
	if !found {
		msg := fmt.Errorf("gittuf did not record a valid approval by your key for tree %.12s; "+
			"the RSL entry for %s may not match the commits shown (the author should run 'gittuf rsl record %s')",
			c.Tree, featureRef, o.Feature)
		if len(rejected) > 0 {
			msg = fmt.Errorf("%w; rejected signatures: %v", msg, rejected)
		}
		return rollback(msg)
	}

	if err := env.Gittuf.ApplyAttestationsLocal(ctx); err != nil {
		return rollback(fmt.Errorf("recording approval in the RSL: %w", err))
	}
	if err := env.Git.PushAtomic(ctx, env.Remote,
		gittufx.AttestationsRef+":"+gittufx.AttestationsRef,
		gittufx.RSLRef+":"+gittufx.RSLRef); err != nil {
		return rollback(fmt.Errorf("pushing approval (nothing was pushed; re-run shipgate approve): %w", err))
	}

	fmt.Fprintf(env.Out, "\napproved %s -> %s at tree %s\nAny new commit or force-push to %s voids this approval.\n",
		featureRef, targetRef, c.Tree, o.Feature)
	return nil
}

func printSummary(ctx context.Context, env change.Env, c *change.Change, me string) error {
	fmt.Fprintf(env.Out, "Approving %s -> %s\n", c.FeatureRef, c.TargetRef)
	fmt.Fprintf(env.Out, "  %s is at   %s\n", c.TargetRef, c.Base)
	fmt.Fprintf(env.Out, "  %s is at   %s\n", c.FeatureRef, c.Tip)
	fmt.Fprintf(env.Out, "  merge tree   %s  (the approval binds to this)\n", c.Tree)
	fmt.Fprintf(env.Out, "  approver     %s\n\nCommits (signer key):\n", me)
	for _, cm := range c.Commits {
		fmt.Fprintf(env.Out, "  %.12s %s  (%s)\n", cm.ID, cm.Subject, cm.Signer.Fingerprint)
	}
	stat, err := env.Git.Output(ctx, "diff", "--stat", c.Base, c.Tree)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "\n%s\n", stat)
	return nil
}
