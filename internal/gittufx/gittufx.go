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
