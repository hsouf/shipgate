// Package change pins down exactly what is being approved or merged: the
// current tip of the target branch, the feature tip, the tree the merge would
// produce, and who signed every commit in between. It also reads the
// approvals gittuf stored for that exact tree and checks their signatures
// independently of gittuf.
//
// shipgate approve (#10, #11) and shipgate merge (#12) are built on it.
package change

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/gitx"
	"github.com/hsouf/shipgate/internal/sshsig"
)

// Signer identifies the key behind a verified signature.
type Signer struct {
	Fingerprint string
	KeyType     string
}

// Verifier checks a signature over message and returns its signer. It must
// return an error unless the signature is valid AND was made by a security
// key that asserted both a touch and a PIN.
type Verifier interface {
	Verify(ctx context.Context, message, armored []byte, namespace string) (Signer, error)
}

// HardwareVerifier is the production Verifier.
type HardwareVerifier struct{}

// Verify implements Verifier.
func (HardwareVerifier) Verify(ctx context.Context, message, armored []byte, namespace string) (Signer, error) {
	sig, err := sshsig.Verify(ctx, armored, message, namespace)
	if err != nil {
		return Signer{}, err
	}
	s := Signer{Fingerprint: sig.PublicKey.Fingerprint(), KeyType: sig.PublicKey.Type}
	switch {
	case !sig.IsSecurityKey():
		return s, fmt.Errorf("signed with a %s key, not a hardware security key", s.KeyType)
	case !sig.UserPresent():
		return s, errors.New("security key signature has no touch (user-presence flag)")
	case !sig.UserVerified():
		return s, errors.New("security key signature has no PIN (user-verification flag)")
	}
	return s, nil
}

// Env holds what approve and merge need to talk to git and gittuf.
type Env struct {
	Git      *gitx.Repo
	Gittuf   gittufx.Tool
	Verifier Verifier
	Remote   string
	Out      io.Writer
}

// Commit is one commit in the change with its verified signer.
type Commit struct {
	ID      string
	Subject string
	Signer  Signer
}

// Change is a proposed merge of FeatureRef into TargetRef.
type Change struct {
	TargetRef  string // e.g. refs/heads/main
	FeatureRef string
	Base       string // current tip of TargetRef
	Tip        string // current tip of FeatureRef
	Tree       string // tree the merge produces; approvals bind to it
	Commits    []Commit
}

// Authors returns the fingerprints of the keys that signed the commits.
func (c *Change) Authors() map[string]bool {
	m := map[string]bool{}
	for _, cm := range c.Commits {
		m[cm.Signer.Fingerprint] = true
	}
	return m
}

// BranchRef turns "feature-x" or "refs/heads/feature-x" into a full ref.
func BranchRef(name string) (string, error) {
	name = strings.TrimPrefix(name, "refs/heads/")
	if name == "" || strings.HasPrefix(name, "refs/") || strings.HasPrefix(name, "-") {
		return "", fmt.Errorf("invalid branch name %q", name)
	}
	return "refs/heads/" + name, nil
}

// Prepare syncs gittuf metadata and both branches from the remote, requires
// local branches to match the remote exactly, and inspects the change.
func Prepare(ctx context.Context, env Env, targetRef, featureRef string) (*Change, error) {
	if err := env.Gittuf.Sync(ctx, env.Remote); err != nil {
		return nil, fmt.Errorf("syncing gittuf metadata from %s: %w", env.Remote, err)
	}
	tracking := func(ref string) string {
		return "refs/remotes/" + env.Remote + "/" + strings.TrimPrefix(ref, "refs/heads/")
	}
	if err := env.Git.Fetch(ctx, env.Remote,
		"+"+targetRef+":"+tracking(targetRef),
		"+"+featureRef+":"+tracking(featureRef)); err != nil {
		return nil, err
	}
	for _, ref := range []string{targetRef, featureRef} {
		if err := matchRemote(ctx, env.Git, ref, tracking(ref)); err != nil {
			return nil, err
		}
	}
	return Inspect(ctx, env, targetRef, featureRef)
}

// matchRemote makes sure the local branch is exactly the remote one, creating
// it if missing. It never overwrites local work.
func matchRemote(ctx context.Context, g *gitx.Repo, ref, remoteRef string) error {
	remote, err := g.ResolveRef(ctx, remoteRef)
	if err != nil {
		return err
	}
	local, err := g.ResolveRef(ctx, ref)
	if errors.Is(err, gitx.ErrNotFound) {
		return g.SetRef(ctx, ref, remote, "")
	}
	if err != nil {
		return err
	}
	if local != remote {
		return fmt.Errorf("local %s (%.12s) differs from %s (%.12s); update it so you act on exactly what is on the remote",
			ref, local, remoteRef, remote)
	}
	return nil
}

// Inspect resolves the change from local refs and verifies every commit's
// signature. Any unsigned commit, or one not signed with touch + PIN on a
// security key, is an error.
func Inspect(ctx context.Context, env Env, targetRef, featureRef string) (*Change, error) {
	base, err := env.Git.ResolveRef(ctx, targetRef)
	if err != nil {
		return nil, err
	}
	tip, err := env.Git.ResolveRef(ctx, featureRef)
	if err != nil {
		return nil, err
	}
	c, err := InspectRange(ctx, env, targetRef, base, tip)
	if err != nil {
		return nil, err
	}
	c.FeatureRef = featureRef
	return c, nil
}

// InspectRange is Inspect for explicit commits: the change that moves
// targetRef from base to the merge of tip.
func InspectRange(ctx context.Context, env Env, targetRef, base, tip string) (*Change, error) {
	c := &Change{TargetRef: targetRef, Base: base, Tip: tip}
	ids, err := env.Git.RevList(ctx, c.Base, c.Tip)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("nothing to merge: %.12s is already in %s", tip, targetRef)
	}
	if c.Tree, err = env.Git.MergeTree(ctx, c.Base, c.Tip); err != nil {
		return nil, err
	}
	for _, id := range ids {
		raw, err := env.Git.CatFile(ctx, "commit", id)
		if err != nil {
			return nil, err
		}
		cm := Commit{ID: id, Subject: gitx.Subject(raw)}
		payload, sig := gitx.SplitCommitSignature(raw)
		if sig == nil {
			return nil, fmt.Errorf("commit %.12s %q is not signed", id, cm.Subject)
		}
		if cm.Signer, err = env.Verifier.Verify(ctx, payload, sig, "git"); err != nil {
			return nil, fmt.Errorf("commit %.12s %q: %w", id, cm.Subject, err)
		}
		c.Commits = append(c.Commits, cm)
	}
	return c, nil
}

// VerifyCommit checks a single commit's signature, e.g. the merge commit.
func VerifyCommit(ctx context.Context, env Env, id string) (Signer, error) {
	raw, err := env.Git.CatFile(ctx, "commit", id)
	if err != nil {
		return Signer{}, err
	}
	payload, sig := gitx.SplitCommitSignature(raw)
	if sig == nil {
		return Signer{}, fmt.Errorf("commit %.12s is not signed", id)
	}
	return env.Verifier.Verify(ctx, payload, sig, "git")
}

// Approvals returns the verified approvers for the exact (Base, Tree) of the
// change, read from gittuf's attestations ref. Signatures that fail
// verification are skipped and described in rejected.
func Approvals(ctx context.Context, env Env, c *Change) (approvers []Signer, rejected []string, err error) {
	p := gittufx.ReferenceAuthorizationPath(c.TargetRef, c.Base, c.Tree)
	blob, err := env.Git.Blob(ctx, gittufx.AttestationsRef, p)
	if errors.Is(err, gitx.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var envl envelope
	if err := json.Unmarshal(blob, &envl); err != nil {
		return nil, nil, fmt.Errorf("approval at %s: %w", p, err)
	}
	payload, err := b64(envl.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("approval at %s: payload: %w", p, err)
	}
	if err := checkStatement(envl.PayloadType, payload, c); err != nil {
		return nil, nil, fmt.Errorf("approval at %s: %w", p, err)
	}
	pae := PAE(envl.PayloadType, payload)
	seen := map[string]bool{}
	for _, s := range envl.Signatures {
		sig, err := b64(s.Sig)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("key %s: %v", s.KeyID, err))
			continue
		}
		signer, err := env.Verifier.Verify(ctx, pae, sig, gittufx.SigNamespace)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("key %s: %v", s.KeyID, err))
			continue
		}
		if !seen[signer.Fingerprint] {
			seen[signer.Fingerprint] = true
			approvers = append(approvers, signer)
		}
	}
	sort.Slice(approvers, func(i, j int) bool { return approvers[i].Fingerprint < approvers[j].Fingerprint })
	return approvers, rejected, nil
}

// Independent returns the approvers whose key signed none of the commits.
func Independent(c *Change, approvers []Signer) []Signer {
	authors := c.Authors()
	var out []Signer
	for _, a := range approvers {
		if !authors[a.Fingerprint] {
			out = append(out, a)
		}
	}
	return out
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		TargetRef string `json:"targetRef"`
		FromID    string `json:"fromID"`
		TargetID  string `json:"targetID"`
	} `json:"predicate"`
}

const (
	inTotoPayloadType = "application/vnd.in-toto+json"
	inTotoStatementV1 = "https://in-toto.io/Statement/v1"
)

// checkStatement makes sure the signed payload says what its storage path
// claims, so a signature can't be moved to approve a different tree.
func checkStatement(payloadType string, payload []byte, c *Change) error {
	if payloadType != inTotoPayloadType {
		return fmt.Errorf("unexpected payload type %q", payloadType)
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return err
	}
	pr := st.Predicate
	switch {
	case st.Type != inTotoStatementV1:
		return fmt.Errorf("unexpected statement type %q", st.Type)
	case st.PredicateType != gittufx.ReferenceAuthorizationPredicate:
		return fmt.Errorf("unexpected predicate type %q", st.PredicateType)
	case pr.TargetRef != c.TargetRef || pr.FromID != c.Base || pr.TargetID != c.Tree:
		return fmt.Errorf("approves %s from %.12s to tree %.12s, not this change", pr.TargetRef, pr.FromID, pr.TargetID)
	case len(st.Subject) != 1 || st.Subject[0].Digest["gitTree"] != c.Tree:
		return errors.New("subject does not match the approved tree")
	}
	return nil
}

// PAE is the DSSE pre-authentication encoding, the bytes actually signed.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func b64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// SigningKey returns git's configured signing key and requires it to be a
// hardware security key: authorship and approval need an enrolled sk key.
func SigningKey(ctx context.Context, g *gitx.Repo) (path string, key sshsig.PublicKey, err error) {
	format, err := g.Config(ctx, "gpg.format")
	if err != nil {
		return "", key, err
	}
	if format != "ssh" {
		return "", key, errors.New("git is not set up to sign with SSH keys (gpg.format != ssh); run shipgate enroll")
	}
	path, err = g.Config(ctx, "user.signingkey")
	if err != nil {
		return "", key, err
	}
	if path == "" {
		return "", key, errors.New("user.signingkey is not set; run shipgate enroll")
	}
	if strings.HasPrefix(path, "key::") {
		return "", key, errors.New("user.signingkey must be a key file path, not a literal key")
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", key, err
		}
		path = filepath.Join(home, path[2:])
	}
	pubPath := path
	if !strings.HasSuffix(pubPath, ".pub") {
		pubPath += ".pub"
	}
	line, err := os.ReadFile(pubPath)
	if err != nil {
		return "", key, fmt.Errorf("reading signing key: %w", err)
	}
	if key, err = sshsig.ParseAuthorizedKey(line); err != nil {
		return "", key, err
	}
	if !sshsig.IsSecurityKeyType(key.Type) {
		return "", key, fmt.Errorf("signing key %s is a %s key, not a hardware security key; run shipgate enroll", path, key.Type)
	}
	return path, key, nil
}
