// Package rslcheck decides, at deploy time, whether a commit was legitimately
// merged into a protected branch (#15). It implements gittufx.PolicyVerifier.
//
// A commit is deployable from ref when all of these hold:
//  1. it is the target of an RSL entry for ref that no annotation skips;
//  2. gittuf verify-ref passes for ref (full history, gittuf policy:
//     enrolled principals, thresholds);
//  3. shipgate's own checks, because gittuf does not check the security-key
//     touch and PIN flags (spike #3):
//     - the RSL entry is signed by a security key with touch + PIN;
//     - every commit the change brings in, and the merge commit, are too;
//     - an approval for the exact (previous entry, tree) exists, signed with
//     touch + PIN by a key that signed none of the change's commits.
//
// The forge's view of the branch is never consulted. Before running gittuf,
// the verifier points ref at its latest RSL entry, so a direct push to the
// forge cannot break verification of legitimate commits; it simply is not
// deployable.
package rslcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/gitx"
)

// Entry is an RSL reference entry.
type Entry struct {
	ID     string // the entry's commit in the RSL
	Ref    string
	Target string
}

// Log is a parsed RSL, newest entry first.
type Log struct {
	Entries []Entry
	Skipped map[string]bool
}

// ReadLog parses refs/gittuf/reference-state-log with plain git.
func ReadLog(ctx context.Context, g *gitx.Repo) (*Log, error) {
	if tip, err := g.RefValue(ctx, gittufx.RSLRef); err != nil {
		return nil, err
	} else if tip == "" {
		return nil, errors.New("repository has no gittuf RSL (refs/gittuf/reference-state-log); set up gittuf and merge with shipgate merge")
	}
	out, err := g.Output(ctx, "log", "--first-parent", "--format=%H%x1f%B%x1e", gittufx.RSLRef)
	if err != nil {
		return nil, fmt.Errorf("reading RSL: %w", err)
	}
	l := &Log{Skipped: map[string]bool{}}
	for _, rec := range strings.Split(out, "\x1e") {
		id, body, ok := strings.Cut(strings.TrimSpace(rec), "\x1f")
		if !ok {
			continue
		}
		header, fields := parseEntry(body)
		switch header {
		case "RSL Reference Entry":
			if fields["ref"] == "" || fields["targetID"] == "" {
				return nil, fmt.Errorf("malformed RSL entry %.12s", id)
			}
			l.Entries = append(l.Entries, Entry{ID: id, Ref: fields["ref"], Target: fields["targetID"]})
		case "RSL Annotation Entry":
			if fields["skip"] == "true" {
				for _, e := range strings.Fields(fields["entryID"]) {
					l.Skipped[e] = true
				}
			}
		}
	}
	return l, nil
}

// parseEntry returns the header line and "key: value" fields. Repeated keys
// (entryID) are joined with spaces.
func parseEntry(body string) (string, map[string]string) {
	lines := strings.Split(body, "\n")
	fields := map[string]string{}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "-----BEGIN") {
			break // annotation message block
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if prev := fields[k]; prev != "" {
			v = prev + " " + v
		}
		fields[k] = strings.TrimSpace(v)
	}
	return strings.TrimSpace(lines[0]), fields
}

// ForRef returns the unskipped entries for ref, newest first.
func (l *Log) ForRef(ref string) []Entry {
	var out []Entry
	for _, e := range l.Entries {
		if e.Ref == ref && !l.Skipped[e.ID] {
			out = append(out, e)
		}
	}
	return out
}

// RefVerifier runs gittuf verify-ref for ref in the repository at dir.
type RefVerifier interface {
	VerifyRef(ctx context.Context, dir, ref string) error
}

// GittufCLI is the production RefVerifier.
type GittufCLI struct{ Bin string }

// VerifyRef implements RefVerifier, returning gittuf's output on failure.
func (c GittufCLI) VerifyRef(ctx context.Context, dir, ref string) error {
	var out bytes.Buffer
	cli := &gittufx.CLI{Bin: c.Bin, Dir: dir, Stderr: &out}
	if err := cli.VerifyRef(ctx, ref); err != nil {
		if msg := strings.TrimSpace(out.String()); msg != "" {
			return fmt.Errorf("%w: %s", err, lastLine(msg))
		}
		return err
	}
	return nil
}

func lastLine(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// Verifier implements gittufx.PolicyVerifier.
type Verifier struct {
	Gittuf     RefVerifier
	Signatures change.Verifier

	mu    sync.Mutex
	cache map[string]result
}

type result struct {
	ok  bool
	err error
	at  time.Time
}

const (
	maxCache = 4096
	// errorTTL bounds how long a failed check is cached, so a transient
	// failure (timeout, missing object) doesn't block a commit until the
	// next RSL change.
	errorTTL = time.Minute
)

var _ gittufx.PolicyVerifier = (*Verifier)(nil)

// CommitVerifiedOnRef implements gittufx.PolicyVerifier. (false, nil) means
// the commit was never legitimately recorded on ref; an error means it was,
// but a check failed.
func (v *Verifier) CommitVerifiedOnRef(ctx context.Context, repoPath, ref, commit string) (bool, error) {
	g := &gitx.Repo{Dir: repoPath}
	// Results depend only on the commit and the gittuf metadata, so cache by
	// their current state.
	state, err := g.Output(ctx, "rev-parse", gittufx.RSLRef, gittufx.AttestationsRef)
	if err != nil {
		// A missing attestations ref is fine for the cache key; a missing RSL
		// is not, and ReadLog reports it.
		state, _ = g.Output(ctx, "rev-parse", gittufx.RSLRef)
	}
	key := strings.Join([]string{repoPath, ref, commit, state}, "|")
	v.mu.Lock()
	if r, ok := v.cache[key]; ok && (r.err == nil || time.Since(r.at) < errorTTL) {
		v.mu.Unlock()
		return r.ok, r.err
	}
	v.mu.Unlock()

	ok, err := v.verify(ctx, g, ref, commit)
	if ctx.Err() == nil { // don't cache timeouts
		v.mu.Lock()
		if v.cache == nil || len(v.cache) >= maxCache {
			v.cache = map[string]result{}
		}
		v.cache[key] = result{ok, err, time.Now()}
		v.mu.Unlock()
	}
	return ok, err
}

func (v *Verifier) verify(ctx context.Context, g *gitx.Repo, ref, commit string) (bool, error) {
	if v.Gittuf == nil || v.Signatures == nil {
		return false, errors.New("rslcheck: verifier not configured")
	}
	full, err := g.Output(ctx, "rev-parse", "--verify", "--quiet", commit+"^{commit}")
	if err != nil {
		return false, nil // commit not in the mirror, so never recorded on ref
	}
	commit = full

	log, err := ReadLog(ctx, g)
	if err != nil {
		return false, err
	}
	entries := log.ForRef(ref)
	idx := -1
	for i, e := range entries {
		if e.Target == commit {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	entry := entries[idx]

	// gittuf compares the ref's tip with its latest RSL entry; use the RSL's
	// view, never the forge's.
	if _, err := g.Output(ctx, "update-ref", ref, entries[0].Target); err != nil {
		return false, err
	}
	if err := v.Gittuf.VerifyRef(ctx, g.Dir, ref); err != nil {
		return false, fmt.Errorf("gittuf verify-ref %s failed: %w", ref, err)
	}

	env := change.Env{Git: g, Verifier: v.Signatures}
	if _, err := change.VerifyCommit(ctx, env, entry.ID); err != nil {
		return false, fmt.Errorf("RSL entry %.12s for %.12s: %w", entry.ID, commit, err)
	}
	if idx+1 >= len(entries) {
		return false, fmt.Errorf("%.12s is the first RSL entry for %s, so there is no approved change to check; deploy a commit merged with shipgate merge", commit, ref)
	}
	prev := entries[idx+1].Target

	tip := commit
	parents, err := g.Output(ctx, "rev-list", "--parents", "-n", "1", commit)
	if err != nil {
		return false, err
	}
	if p := strings.Fields(parents); len(p) == 3 && p[1] == prev {
		// A shipgate merge: the merge commit must be hardware-signed too.
		if _, err := change.VerifyCommit(ctx, env, commit); err != nil {
			return false, fmt.Errorf("merge commit %.12s: %w", commit, err)
		}
		tip = p[2]
	}

	c, err := change.InspectRange(ctx, env, ref, prev, tip)
	if err != nil {
		return false, err
	}
	tree, err := g.Output(ctx, "rev-parse", commit+"^{tree}")
	if err != nil {
		return false, err
	}
	if tree != c.Tree {
		return false, fmt.Errorf("%.12s does not have the tree of merging %.12s into %.12s, so no approval can cover it", commit, tip, prev)
	}
	approvers, rejected, err := change.Approvals(ctx, env, c)
	if err != nil {
		return false, err
	}
	if len(change.Independent(c, approvers)) == 0 {
		reason := "no approval from a second person's security key for this change"
		if len(approvers) > 0 {
			reason = "the only approvals are from keys that signed commits in the change"
		}
		if len(rejected) > 0 {
			reason += "; rejected signatures: " + strings.Join(rejected, "; ")
		}
		return false, fmt.Errorf("%.12s on %s: %s", commit, ref, reason)
	}
	return true, nil
}
