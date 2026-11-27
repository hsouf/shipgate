// Package gittufx is a thin wrapper around gittuf. Everything shipgate needs
// from gittuf goes through this package so the integration choice (Go API in
// github.com/gittuf/gittuf/experimental/gittuf vs shelling out to the CLI)
// can change in one place. See spike #4.
//
// Open question (spike #3): does gittuf enforce the user-presence and
// user-verification flags on SSH security-key signatures? If not, shipgate
// must check them itself before trusting gittuf's result.
package gittufx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
)

// PolicyVerifier answers whether a commit is the target of a verified RSL
// entry on a protected ref, under the repository's gittuf policy.
type PolicyVerifier interface {
	CommitVerifiedOnRef(ctx context.Context, repoPath, ref, commit string) (bool, error)
}

// NotImplemented always fails, so the gate fails closed.
type NotImplemented struct{}

func (NotImplemented) CommitVerifiedOnRef(context.Context, string, string, string) (bool, error) {
	return false, errors.New("gittuf policy verification not implemented (#15)")
}

// Refs and layout used by gittuf v0.18. shipgate reads them with plain git so
// it can check approvals independently of the gittuf binary.
const (
	RSLRef          = "refs/gittuf/reference-state-log"
	AttestationsRef = "refs/gittuf/attestations"
	// SigNamespace is the SSHSIG namespace gittuf uses for DSSE signatures.
	SigNamespace = "git"
	// ReferenceAuthorizationPredicate is the in-toto predicate type of the
	// approvals gittuf writes for branches.
	ReferenceAuthorizationPredicate = "https://gittuf.dev/reference-authorization/v0.2"
)

// ReferenceAuthorizationPath is where gittuf stores the approvals for moving
// targetRef from commit fromID to tree toTreeID, inside AttestationsRef.
func ReferenceAuthorizationPath(targetRef, fromID, toTreeID string) string {
	return path.Join("reference-authorizations", targetRef, fromID+"-"+toTreeID)
}

// CLI drives the gittuf command-line tool. Spike #4: the Go API needs a much
// newer Go toolchain (gittuf v0.18 requires go 1.27) and pulls in a large
// dependency tree, so v0.1 shells out to the CLI instead.
type CLI struct {
	Bin string // path to gittuf; "" looks it up in PATH
	Dir string // repository working directory
	// Stderr receives gittuf output, including key touch and PIN prompts.
	Stderr io.Writer
}

func (c *CLI) run(ctx context.Context, args ...string) error {
	bin := c.Bin
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("gittuf"); err != nil {
			return errors.New("gittuf not found in PATH; install it from https://gittuf.dev")
		}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = c.Dir
	cmd.Stdin = os.Stdin
	cmd.Stdout, cmd.Stderr = c.stderr(), c.stderr()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gittuf %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (c *CLI) stderr() io.Writer {
	if c.Stderr != nil {
		return c.Stderr
	}
	return os.Stderr
}

// Sync reconciles the local RSL with remote.
func (c *CLI) Sync(ctx context.Context, remote string) error {
	return c.run(ctx, "sync", remote)
}

// Authorize signs a reference authorization (approval) for merging featureRef
// into targetRef, bound to the merge tree gittuf computes from the RSL. It
// commits to AttestationsRef locally; nothing is pushed.
func (c *CLI) Authorize(ctx context.Context, signingKey, targetRef, featureRef string) error {
	return c.run(ctx, "attest", "authorize", "--signing-key", signingKey, "--from-ref", featureRef, targetRef)
}

// ApplyAttestationsLocal records the attestations ref in the local RSL.
func (c *CLI) ApplyAttestationsLocal(ctx context.Context) error {
	return c.run(ctx, "attest", "apply", "--local-only")
}

// VerifyMergeable checks gittuf policy (enrolled principals, thresholds)
// for merging featureRef into baseRef.
func (c *CLI) VerifyMergeable(ctx context.Context, baseRef, featureRef string) error {
	return c.run(ctx, "verify-mergeable", "--base-branch", baseRef, "--feature-branch", featureRef)
}

// RecordLocal adds a signed RSL entry for ref's current tip, locally only.
func (c *CLI) RecordLocal(ctx context.Context, ref string) error {
	return c.run(ctx, "rsl", "record", "--local-only", ref)
}

// VerifyRef verifies ref's full RSL history against policy.
func (c *CLI) VerifyRef(ctx context.Context, ref string) error {
	return c.run(ctx, "verify-ref", ref)
}

// Tool is the subset of gittuf that approve and merge use. CLI implements it;
// tests use fakes.
type Tool interface {
	Sync(ctx context.Context, remote string) error
	Authorize(ctx context.Context, signingKey, targetRef, featureRef string) error
	ApplyAttestationsLocal(ctx context.Context) error
	VerifyMergeable(ctx context.Context, baseRef, featureRef string) error
	RecordLocal(ctx context.Context, ref string) error
	VerifyRef(ctx context.Context, ref string) error
}

var _ Tool = (*CLI)(nil)
