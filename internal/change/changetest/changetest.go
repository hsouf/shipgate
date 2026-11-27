// Package changetest builds real git repositories with fake signatures and a
// fake gittuf, so approve and merge can be tested without a physical key or
// the gittuf binary. It is imported only by tests; the fake signature format
// is accepted only by FakeVerifier, never by change.HardwareVerifier.
package changetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/gitx"
	"github.com/hsouf/shipgate/internal/sshsig"
)

// Person is a test identity with a fake security-key public key.
type Person struct {
	Name    string
	KeyPath string // path to the .pub file
	Key     sshsig.PublicKey
}

// FP returns the person's key fingerprint.
func (p Person) FP() string { return p.Key.Fingerprint() }

// Sign produces a fake signature that FakeVerifier accepts for message.
func (p Person) Sign(message []byte) []byte { return fakeSig(p.FP(), message) }

func fakeSig(fp string, message []byte) []byte {
	sum := sha256.Sum256(message)
	return []byte("TESTSIG " + fp + " " + hex.EncodeToString(sum[:]) + "\n")
}

// FakeVerifier accepts only TESTSIG signatures over the exact message.
type FakeVerifier struct{}

// Verify implements change.Verifier.
func (FakeVerifier) Verify(_ context.Context, message, armored []byte, _ string) (change.Signer, error) {
	f := strings.Fields(string(armored))
	if len(f) != 3 || f[0] != "TESTSIG" {
		return change.Signer{}, errors.New("not signed with a security key (test)")
	}
	sum := sha256.Sum256(message)
	if f[2] != hex.EncodeToString(sum[:]) {
		return change.Signer{}, errors.New("signature does not match message (test)")
	}
	return change.Signer{Fingerprint: f[1], KeyType: sshsig.TypeSKEd25519}, nil
}

// Env is a working clone plus a bare origin.
type Env struct {
	T      *testing.T
	Dir    string
	Origin string
	Git    *gitx.Repo
	Gittuf *FakeGittuf
	Out    bytes.Buffer
	n      int
}

// New creates a clone with an origin remote and initial main commit signed by
// author, pushed to origin.
func New(t *testing.T, author Person) *Env {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	e := &Env{T: t, Dir: filepath.Join(root, "work"), Origin: filepath.Join(root, "origin.git")}
	e.Git = &gitx.Repo{Dir: e.Dir, Stderr: io.Discard}
	run(t, root, "init", "-q", "--bare", "-b", "main", e.Origin)
	run(t, root, "init", "-q", "-b", "main", e.Dir)
	e.Run("remote", "add", "origin", e.Origin)
	e.Run("config", "user.name", "test")
	e.Run("config", "user.email", "test@example.com")
	e.Gittuf = &FakeGittuf{Env: e}
	base := e.Commit(author, nil, map[string]string{"README": "hello\n"}, "initial")
	e.Run("update-ref", "refs/heads/main", base)
	e.Run("reset", "-q", "--hard", "main")
	e.Run("push", "-q", "origin", "main")
	return e
}

// ChangeEnv returns the change.Env for this repo.
func (e *Env) ChangeEnv() change.Env {
	return change.Env{Git: e.Git, Gittuf: e.Gittuf, Verifier: FakeVerifier{}, Remote: "origin", Out: &e.Out}
}

// NewPerson writes a fake sk public key for name.
func (e *Env) NewPerson(name string) Person {
	return NewPerson(e.T, name)
}

// NewPerson writes a fake sk public key for name in a temp dir.
func NewPerson(t *testing.T, name string) Person {
	t.Helper()
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	pk := sha256.Sum256([]byte(name))
	blob := bytes.Join([][]byte{str([]byte(sshsig.TypeSKEd25519)), str(pk[:]), str([]byte("ssh:"))}, nil)
	path := filepath.Join(t.TempDir(), name+".pub")
	line := sshsig.TypeSKEd25519 + " " + base64.StdEncoding.EncodeToString(blob) + " " + name + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := sshsig.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return Person{Name: name, KeyPath: path, Key: key}
}

// UseKey configures git in the clone to sign as p.
func (e *Env) UseKey(p Person) {
	e.Run("config", "gpg.format", "ssh")
	e.Run("config", "user.signingkey", p.KeyPath)
}

// Run runs git in the clone and returns trimmed stdout.
func (e *Env) Run(args ...string) string {
	e.T.Helper()
	return run(e.T, e.Dir, args...)
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Tree writes files (path -> content) on top of the tree of base ("" for
// empty) and returns the tree ID.
func (e *Env) Tree(base string, files map[string]string) string {
	e.T.Helper()
	idx := filepath.Join(e.T.TempDir(), "index")
	withIdx := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = e.Dir
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+idx)
		out, err := cmd.CombinedOutput()
		if err != nil {
			e.T.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if base != "" {
		withIdx("read-tree", base)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		blob := e.hashObject("blob", []byte(files[p]))
		withIdx("update-index", "--add", "--cacheinfo", "100644,"+blob+","+p)
	}
	return withIdx("write-tree")
}

func (e *Env) hashObject(kind string, data []byte) string {
	e.T.Helper()
	cmd := exec.Command("git", "hash-object", "-t", kind, "-w", "--stdin")
	cmd.Dir = e.Dir
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.T.Fatalf("hash-object: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// Commit creates a commit with files applied on top of the first parent's
// tree, signed by signer (zero Person = unsigned).
func (e *Env) Commit(signer Person, parents []string, files map[string]string, subject string) string {
	e.T.Helper()
	base := ""
	if len(parents) > 0 {
		base = parents[0]
	}
	return e.CommitTree(signer, e.Tree(base, files), parents, subject)
}

// CommitTree creates a commit object for tree, signed by signer.
func (e *Env) CommitTree(signer Person, tree string, parents []string, msg string) string {
	e.T.Helper()
	e.n++
	var h strings.Builder
	fmt.Fprintf(&h, "tree %s\n", tree)
	for _, p := range parents {
		fmt.Fprintf(&h, "parent %s\n", p)
	}
	ts := fmt.Sprintf("%d +0000", 1700000000+e.n)
	fmt.Fprintf(&h, "author test <test@example.com> %s\ncommitter test <test@example.com> %s\n", ts, ts)
	headers := h.String()
	body := "\n" + strings.TrimRight(msg, "\n") + "\n"
	raw := headers + body
	if signer.Name != "" {
		sig := signer.Sign([]byte(raw))
		raw = headers + "gpgsig " + string(sig) + body
	}
	return e.hashObject("commit", []byte(raw))
}

// Push pushes refs to origin, forcing.
func (e *Env) Push(ref, commit string) {
	e.T.Helper()
	e.Run("push", "-q", "-f", "origin", commit+":"+ref)
}

// WriteApproval stores a gittuf-format approval envelope for (target, base,
// tree) signed by the given people, on top of the local attestations ref.
func (e *Env) WriteApproval(target, base, tree string, signers ...Person) {
	e.T.Helper()
	e.writeApproval(target, base, tree, tree, signers...)
}

func (e *Env) writeApproval(target, base, pathTree, claimedTree string, signers ...Person) {
	e.T.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]string{"gitTree": claimedTree}}},
		"predicateType": gittufx.ReferenceAuthorizationPredicate,
		"predicate":     map[string]string{"targetRef": target, "fromID": base, "targetID": claimedTree},
	}
	payload, _ := json.Marshal(st)
	const pt = "application/vnd.in-toto+json"
	pae := change.PAE(pt, payload)
	p := gittufx.ReferenceAuthorizationPath(target, base, pathTree)

	type sig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	var sigs []sig
	if old, err := e.Git.Blob(context.Background(), gittufx.AttestationsRef, p); err == nil {
		var env struct {
			Signatures []sig `json:"signatures"`
		}
		_ = json.Unmarshal(old, &env)
		sigs = env.Signatures
	}
	for _, s := range signers {
		sigs = append(sigs, sig{KeyID: s.FP(), Sig: base64.StdEncoding.EncodeToString(s.Sign(pae))})
	}
	envJSON, _ := json.Marshal(map[string]any{
		"payloadType": pt,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  sigs,
	})

	prev := e.Run("for-each-ref", "--format=%(objectname)", gittufx.AttestationsRef)
	var parents []string
	baseTree := ""
	if prev != "" {
		parents = []string{prev}
		baseTree = prev
	}
	blob := e.hashObject("blob", envJSON)
	idx := filepath.Join(e.T.TempDir(), "index")
	withIdx := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = e.Dir
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+idx)
		out, err := cmd.CombinedOutput()
		if err != nil {
			e.T.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if baseTree != "" {
		withIdx("read-tree", baseTree)
	}
	withIdx("update-index", "--add", "--cacheinfo", "100644,"+blob+","+p)
	tree := withIdx("write-tree")
	c := e.CommitTree(Person{}, tree, parents, "attestations")
	e.Run("update-ref", gittufx.AttestationsRef, c)
}

// AppendRSL adds an (unsigned, fake) entry commit to the local RSL.
func (e *Env) AppendRSL(msg string) {
	e.T.Helper()
	prev := e.Run("for-each-ref", "--format=%(objectname)", gittufx.RSLRef)
	var parents []string
	if prev != "" {
		parents = []string{prev}
	}
	c := e.CommitTree(Person{}, e.Tree("", nil), parents, msg)
	e.Run("update-ref", gittufx.RSLRef, c)
}

// FakeGittuf emulates the gittuf CLI calls shipgate makes.
type FakeGittuf struct {
	Env *Env
	// Approver signs in Authorize.
	Approver Person
	// AuthorizeWrongTree makes Authorize record an approval for a different
	// tree, as gittuf would if its RSL disagreed with the local branches.
	AuthorizeWrongTree bool
	VerifyMergeableErr error
	VerifyRefErr       error
	Calls              []string
}

// Sync implements gittufx.Tool.
func (f *FakeGittuf) Sync(context.Context, string) error {
	f.Calls = append(f.Calls, "sync")
	return nil
}

// Authorize implements gittufx.Tool.
func (f *FakeGittuf) Authorize(ctx context.Context, _, targetRef, featureRef string) error {
	f.Calls = append(f.Calls, "authorize")
	g := f.Env.Git
	base, err := g.ResolveRef(ctx, targetRef)
	if err != nil {
		return err
	}
	tip, err := g.ResolveRef(ctx, featureRef)
	if err != nil {
		return err
	}
	tree, err := g.MergeTree(ctx, base, tip)
	if err != nil {
		return err
	}
	if f.AuthorizeWrongTree {
		tree = f.Env.Tree("", map[string]string{"other": "x"})
	}
	f.Env.WriteApproval(targetRef, base, tree, f.Approver)
	return nil
}

// ApplyAttestationsLocal implements gittufx.Tool.
func (f *FakeGittuf) ApplyAttestationsLocal(context.Context) error {
	f.Calls = append(f.Calls, "apply")
	f.Env.AppendRSL("attestations entry")
	return nil
}

// VerifyMergeable implements gittufx.Tool.
func (f *FakeGittuf) VerifyMergeable(context.Context, string, string) error {
	f.Calls = append(f.Calls, "verify-mergeable")
	return f.VerifyMergeableErr
}

// RecordLocal implements gittufx.Tool.
func (f *FakeGittuf) RecordLocal(_ context.Context, ref string) error {
	f.Calls = append(f.Calls, "record "+ref)
	f.Env.AppendRSL("entry " + ref)
	return nil
}

// VerifyRef implements gittufx.Tool.
func (f *FakeGittuf) VerifyRef(context.Context, string) error {
	f.Calls = append(f.Calls, "verify-ref")
	return f.VerifyRefErr
}

// WriteApprovalClaiming writes an approval stored at the path for pathTree
// whose signed statement claims claimedTree, to test that a signature can't
// be moved to approve a different tree.
func (e *Env) WriteApprovalClaiming(target, base, pathTree, claimedTree string, signers ...Person) {
	e.T.Helper()
	e.writeApproval(target, base, pathTree, claimedTree, signers...)
}

// RecordRSL appends a gittuf-format RSL reference entry for ref -> target,
// signed by signer (zero Person = unsigned), and returns the entry ID.
func (e *Env) RecordRSL(signer Person, ref, target string) string {
	e.T.Helper()
	return e.appendRSLEntry(signer, fmt.Sprintf("RSL Reference Entry\n\nref: %s\ntargetID: %s\n", ref, target))
}

// SkipRSL appends an annotation entry that marks entryIDs as skipped.
func (e *Env) SkipRSL(signer Person, entryIDs ...string) string {
	e.T.Helper()
	msg := "RSL Annotation Entry\n\n"
	for _, id := range entryIDs {
		msg += "entryID: " + id + "\n"
	}
	return e.appendRSLEntry(signer, msg+"skip: true\n")
}

func (e *Env) appendRSLEntry(signer Person, msg string) string {
	prev := e.Run("for-each-ref", "--format=%(objectname)", gittufx.RSLRef)
	var parents []string
	if prev != "" {
		parents = []string{prev}
	}
	c := e.CommitTree(signer, e.Tree("", nil), parents, msg)
	e.Run("update-ref", gittufx.RSLRef, c)
	return c
}
