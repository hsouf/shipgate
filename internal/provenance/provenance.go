// Package provenance verifies SLSA build provenance for an image and extracts
// the source repository and commit it was built from.
//
// TODO(#13): implement with sigstore-go. Verify the provenance signature,
// check the builder identity against an allowlist, and bind the attestation
// subject digest to the image digest being deployed.
package provenance

import (
	"context"
	"errors"
)

// Source is what a verified provenance statement tells us.
type Source struct {
	Repo    string // e.g. github.com/acme/app
	Commit  string // full commit SHA
	Builder string // verified builder identity
}

// Verifier verifies provenance for an image reference pinned by digest.
type Verifier interface {
	Verify(ctx context.Context, image string) (Source, error)
}

// NotImplemented always fails, so the gate fails closed.
type NotImplemented struct{}

func (NotImplemented) Verify(context.Context, string) (Source, error) {
	return Source{}, errors.New("provenance verification not implemented (#13)")
}
