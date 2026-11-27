// Package provenance ties a container image to the source commit it was
// built from, using Sigstore-signed build provenance (#13).
//
// Design:
//   - Provenance is a Sigstore bundle (DSSE + in-toto SLSA statement) signed
//     keylessly by the CI system. sigstore-go verifies the signature, the
//     Fulcio certificate chain, transparency log and timestamps, and that the
//     statement's subject is the image digest being deployed.
//   - The source repo and commit are taken from the Fulcio certificate
//     (SourceRepositoryURI, SourceRepositoryDigest). Those come from the CI's
//     OIDC token, so a modified workflow can't forge them. The SLSA predicate
//     is written by the build itself and is only cross-checked: if it names a
//     different commit for the source repo, the image is denied.
//   - The builder policy (Policy) decides which CI identities count: trusted
//     OIDC issuers, hosted runners only, which triggers, and which workflow
//     may sign. It works for any CI that Fulcio issues certificates for
//     (GitHub Actions, GitLab, Buildkite, ...).
//   - Keyless signatures are NOT authorship (AGENTS.md rule 4): provenance
//     only says which commit was built. Whether that commit may ship is
//     decided by the gittuf checks that follow.
package provenance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Source is what a verified provenance statement tells us.
type Source struct {
	Repo    string // e.g. github.com/acme/app
	Commit  string // full commit SHA
	Builder string // verified builder identity (workflow that signed)
}

// Verifier verifies provenance for an image reference pinned by digest.
type Verifier interface {
	Verify(ctx context.Context, image string) (Source, error)
}

// NotImplemented always fails, so the gate fails closed.
type NotImplemented struct{}

func (NotImplemented) Verify(context.Context, string) (Source, error) {
	return Source{}, errors.New("provenance verification not configured; pass --repo for the repositories images may be built from")
}

// Attestation is the content of a cryptographically verified bundle.
type Attestation struct {
	Identity      Identity
	PredicateType string
	Predicate     []byte // JSON
}

// Identity holds the Fulcio certificate fields the policy uses.
type Identity struct {
	Issuer           string // OIDC issuer
	SourceRepoURI    string // e.g. https://github.com/acme/app
	SourceRepoDigest string // commit the workflow ran on
	SourceRepoRef    string
	SignerURI        string // workflow that signed, e.g. .../release.yml@refs/heads/main
	SignerDigest     string // commit of that workflow file
	Trigger          string // event, e.g. push
	RunnerEnv        string // github-hosted, self-hosted, ...
}

// BundleSource finds provenance bundles for an image.
type BundleSource interface {
	Bundles(ctx context.Context, image string) ([][]byte, error)
}

// BundleVerifier checks a bundle cryptographically and that its subject is
// the given artifact digest.
type BundleVerifier interface {
	VerifyBundle(ctx context.Context, bundleJSON []byte, digestAlg string, digest []byte) (*Attestation, error)
}

// Sigstore is the production Verifier.
type Sigstore struct {
	Source   BundleSource
	Bundles  BundleVerifier
	Policy   Policy
	MaxTried int // bundles tried per image; default 16
}

// Verify implements Verifier.
func (s *Sigstore) Verify(ctx context.Context, image string) (Source, error) {
	digest, err := imageDigest(image)
	if err != nil {
		return Source{}, err
	}
	bundles, err := s.Source.Bundles(ctx, image)
	if err != nil {
		return Source{}, fmt.Errorf("fetching provenance: %w", err)
	}
	if len(bundles) == 0 {
		return Source{}, errors.New("no Sigstore provenance found for the image; attest builds with e.g. actions/attest-build-provenance (push-to-registry: true)")
	}
	limit := s.MaxTried
	if limit == 0 {
		limit = 16
	}
	var reasons []string
	for i, b := range bundles {
		if i >= limit {
			reasons = append(reasons, fmt.Sprintf("%d more bundles not tried", len(bundles)-limit))
			break
		}
		att, err := s.Bundles.VerifyBundle(ctx, b, "sha256", digest)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		src, err := s.Policy.Evaluate(att)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		return src, nil
	}
	return Source{}, fmt.Errorf("no acceptable provenance: %s", strings.Join(dedupe(reasons), "; "))
}

func imageDigest(image string) ([]byte, error) {
	_, hexDigest, ok := strings.Cut(image, "@sha256:")
	if !ok || len(hexDigest) != 64 {
		return nil, errors.New("image is not pinned by a sha256 digest")
	}
	b, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid image digest: %w", err)
	}
	return b, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
