// Package gitx runs the git plumbing shipgate needs. It shells out to git
// rather than linking a git library, to keep the dependency tree small.
package gitx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when a ref or object does not exist.
var ErrNotFound = errors.New("not found")

// Repo is a git working directory.
type Repo struct {
	Dir string
	// Stderr receives git's progress and prompts for commands that may need
	// the user (signing, push). Defaults to os.Stderr.
	Stderr io.Writer
}

func (r *Repo) cmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = r.Dir
	return c
}

// Output runs git and returns trimmed stdout.
func (r *Repo) Output(ctx context.Context, args ...string) (string, error) {
	out, err := r.Raw(ctx, nil, args...)
	return strings.TrimSpace(string(out)), err
}

// Raw runs git with optional stdin and returns stdout untouched.
func (r *Repo) Raw(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	c := r.cmd(ctx, args...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Interactive runs git with the user's terminal attached to stdin and stderr,
// so security-key touch and PIN prompts reach them. Stdout is returned.
func (r *Repo) Interactive(ctx context.Context, args ...string) (string, error) {
	c := r.cmd(ctx, args...)
	c.Stdin = os.Stdin
	c.Stderr = r.stderr()
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Repo) stderr() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return os.Stderr
}

// Config returns a git config value, or "" if unset.
func (r *Repo) Config(ctx context.Context, key string) (string, error) {
	out, err := r.Output(ctx, "config", "--get", key)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return "", nil
	}
	return out, err
}

// ResolveRef returns the commit a ref points to, or ErrNotFound.
func (r *Repo) ResolveRef(ctx context.Context, ref string) (string, error) {
	out, err := r.Output(ctx, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return "", fmt.Errorf("%s: %w", ref, ErrNotFound)
		}
		return "", err
	}
	return out, nil
}

// RefValue returns the object a ref points to without peeling, or "" if the
// ref does not exist. Use it to snapshot refs before changing them.
func (r *Repo) RefValue(ctx context.Context, ref string) (string, error) {
	out, err := r.Output(ctx, "rev-parse", "--verify", "--quiet", ref)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return "", nil
	}
	return out, err
}

// SetRef moves ref from old to new atomically. An empty old means the ref
// must not exist; an empty new deletes it.
func (r *Repo) SetRef(ctx context.Context, ref, newValue, old string) error {
	if newValue == "" {
		_, err := r.Output(ctx, "update-ref", "-d", ref, old)
		return err
	}
	if old == "" {
		old = strings.Repeat("0", 40)
	}
	_, err := r.Output(ctx, "update-ref", ref, newValue, old)
	return err
}

// RestoreRef sets ref back to value, deleting it when value is "". Use it only
// to roll back refs this process changed.
func (r *Repo) RestoreRef(ctx context.Context, ref, value string) error {
	if value != "" {
		_, err := r.Output(ctx, "update-ref", ref, value)
		return err
	}
	cur, err := r.RefValue(ctx, ref)
	if err != nil || cur == "" {
		return err
	}
	return r.SetRef(ctx, ref, "", cur)
}

// MergeTree computes the tree a merge of feature into base would produce,
// using the same command gittuf uses to compute the tree an approval binds to.
func (r *Repo) MergeTree(ctx context.Context, base, feature string) (string, error) {
	out, err := r.Output(ctx, "merge-tree", "--write-tree", base, feature)
	if err != nil {
		return "", fmt.Errorf("%s does not merge cleanly into %s; merge or rebase first: %w", feature, base, err)
	}
	tree, _, _ := strings.Cut(out, "\n")
	return tree, nil
}

// RevList returns commits reachable from tip but not from base, oldest first.
func (r *Repo) RevList(ctx context.Context, base, tip string) ([]string, error) {
	out, err := r.Output(ctx, "rev-list", "--reverse", base+".."+tip)
	if err != nil || out == "" {
		return nil, err
	}
	return strings.Split(out, "\n"), nil
}

// CatFile returns the raw content of an object.
func (r *Repo) CatFile(ctx context.Context, kind, object string) ([]byte, error) {
	return r.Raw(ctx, nil, "cat-file", kind, object)
}

// Blob returns the blob at path in treeish, or ErrNotFound.
func (r *Repo) Blob(ctx context.Context, treeish, path string) ([]byte, error) {
	spec := treeish + ":" + path
	if _, err := r.Output(ctx, "cat-file", "-e", spec); err != nil {
		return nil, fmt.Errorf("%s: %w", spec, ErrNotFound)
	}
	return r.CatFile(ctx, "blob", spec)
}

// Fetch updates refs from remote with explicit refspecs.
func (r *Repo) Fetch(ctx context.Context, remote string, refspecs ...string) error {
	args := append([]string{"fetch", "--quiet", "--no-tags", remote}, refspecs...)
	_, err := r.Output(ctx, args...)
	return err
}

// PushAtomic pushes refspecs all-or-nothing and never forces.
func (r *Repo) PushAtomic(ctx context.Context, remote string, refspecs ...string) error {
	for _, s := range refspecs {
		if strings.HasPrefix(s, "+") {
			return fmt.Errorf("refusing to force-push %q", s)
		}
	}
	args := append([]string{"push", "--atomic", "--porcelain", remote}, refspecs...)
	_, err := r.Output(ctx, args...)
	return err
}

// CurrentBranch returns the ref HEAD points to, or "" when detached.
func (r *Repo) CurrentBranch(ctx context.Context) (string, error) {
	out, err := r.Output(ctx, "symbolic-ref", "-q", "HEAD")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return "", nil
	}
	return out, err
}

// SplitCommitSignature splits a raw commit object into the signed payload and
// the armored signature from its gpgsig header, matching what git verifies.
// sig is nil if the commit is unsigned.
func SplitCommitSignature(raw []byte) (payload, sig []byte) {
	var out, sigBuf bytes.Buffer
	lines := bytes.SplitAfter(raw, []byte("\n"))
	inHeader, inSig := true, false
	for _, line := range lines {
		if inHeader {
			if inSig && bytes.HasPrefix(line, []byte(" ")) {
				sigBuf.Write(line[1:])
				continue
			}
			inSig = false
			if bytes.HasPrefix(line, []byte("gpgsig ")) {
				inSig = true
				sigBuf.Write(line[len("gpgsig "):])
				continue
			}
			if bytes.Equal(line, []byte("\n")) {
				inHeader = false
			}
		}
		out.Write(line)
	}
	if sigBuf.Len() == 0 {
		return raw, nil
	}
	return out.Bytes(), sigBuf.Bytes()
}

// Subject returns the first line of a raw commit's message.
func Subject(raw []byte) string {
	_, msg, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		return ""
	}
	line, _, _ := bytes.Cut(msg, []byte("\n"))
	return string(line)
}
