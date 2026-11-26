// Package mirror keeps local mirrors of source repositories, including the
// gittuf refs (refs/gittuf/*), so deploy decisions never depend on live
// access to the forge.
//
// TODO(#14): implement periodic sync, a staleness bound, and a configurable
// fail-open / fail-closed behaviour when the mirror is stale. Default must be
// fail-closed.
package mirror

import (
	"context"
	"errors"
)

// Mirror returns a local path to an up-to-date mirror of repo.
type Mirror interface {
	Sync(ctx context.Context, repo string) (path string, err error)
}

// NotImplemented always fails, so the gate fails closed.
type NotImplemented struct{}

func (NotImplemented) Sync(context.Context, string) (string, error) {
	return "", errors.New("repo mirror not implemented (#14)")
}
