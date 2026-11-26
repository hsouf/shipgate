// Package gate implements the deploy decision:
//
//	image digest
//	  -> verify SLSA provenance, trusted builder only     (provenance, #13)
//	  -> extract source repo + commit
//	  -> fetch repo incl. refs/gittuf/* from a mirror     (mirror, #14)
//	  -> gittuf verify-ref on the protected branch        (gittufx, #15)
//	  -> confirm commit matches a verified RSL entry      (#15)
//	  -> allow, or deny with a reason
//
// The gate fails closed: any step that errors or is not implemented yields a
// deny. Audit-only behaviour belongs to callers (see internal/webhook), never
// here, so the decision itself is always honest.
package gate

import (
	"context"
	"errors"
	"strings"

	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/mirror"
	"github.com/hsouf/shipgate/internal/provenance"
)

// ErrDenied is returned by CLI callers when a decision is a deny.
var ErrDenied = errors.New("deploy denied")

// Request is one image to evaluate.
type Request struct {
	Image string `json:"image"`
}

// Check is the outcome of one pipeline step.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Decision is the gate's answer for one image.
type Decision struct {
	Image      string  `json:"image"`
	Allowed    bool    `json:"allowed"`
	Reason     string  `json:"reason"`
	SourceRepo string  `json:"source_repo,omitempty"`
	Commit     string  `json:"commit,omitempty"`
	Checks     []Check `json:"checks"`
}

// Config wires the pipeline's dependencies. Nil fields use the default
// (currently not-implemented, therefore deny) implementations.
type Config struct {
	Provenance provenance.Verifier
	Mirror     mirror.Mirror
	Policy     gittufx.PolicyVerifier
	// ProtectedRefs lists the refs a deployable commit must be verified on.
	ProtectedRefs []string
}

// Verifier runs the pipeline.
type Verifier struct{ cfg Config }

// NewVerifier returns a Verifier with defaults filled in.
func NewVerifier(cfg Config) *Verifier {
	if cfg.Provenance == nil {
		cfg.Provenance = provenance.NotImplemented{}
	}
	if cfg.Mirror == nil {
		cfg.Mirror = mirror.NotImplemented{}
	}
	if cfg.Policy == nil {
		cfg.Policy = gittufx.NotImplemented{}
	}
	if len(cfg.ProtectedRefs) == 0 {
		cfg.ProtectedRefs = []string{"refs/heads/main"}
	}
	return &Verifier{cfg: cfg}
}

// Verify evaluates one image. It never panics and never returns an error:
// every failure is expressed as a deny with a reason.
func (v *Verifier) Verify(ctx context.Context, req Request) Decision {
	d := Decision{Image: req.Image}

	if !strings.Contains(req.Image, "@sha256:") {
		return d.deny("digest", "image is not pinned by digest; tags are mutable and cannot be verified")
	}
	d.pass("digest", "")

	src, err := v.cfg.Provenance.Verify(ctx, req.Image)
	if err != nil {
		return d.deny("provenance", err.Error())
	}
	d.SourceRepo, d.Commit = src.Repo, src.Commit
	d.pass("provenance", "builder "+src.Builder)

	repoPath, err := v.cfg.Mirror.Sync(ctx, src.Repo)
	if err != nil {
		return d.deny("mirror", err.Error())
	}
	d.pass("mirror", repoPath)

	for _, ref := range v.cfg.ProtectedRefs {
		ok, err := v.cfg.Policy.CommitVerifiedOnRef(ctx, repoPath, ref, src.Commit)
		if err != nil {
			return d.deny("policy", err.Error())
		}
		if ok {
			d.pass("policy", "commit matches a verified RSL entry on "+ref)
			d.Allowed = true
			d.Reason = "verified"
			return d
		}
	}
	return d.deny("policy", "commit is not a verified RSL entry on any protected ref")
}

func (d *Decision) pass(name, detail string) {
	d.Checks = append(d.Checks, Check{Name: name, Passed: true, Detail: detail})
}

func (d Decision) deny(name, reason string) Decision {
	d.Checks = append(d.Checks, Check{Name: name, Passed: false, Detail: reason})
	d.Allowed = false
	d.Reason = name + ": " + reason
	return d
}
