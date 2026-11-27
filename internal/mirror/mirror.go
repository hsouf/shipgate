// Package mirror keeps local mirrors of source repositories, including the
// gittuf refs (refs/gittuf/*), so deploy decisions never depend on live
// access to the forge.
//
// Layout of a mirror (a bare git repository):
//
//	refs/remotes/forge/heads/*   branches as the forge reports them; untrusted
//	refs/gittuf/*                gittuf metadata; the RSL, attestations and
//	                             policy only ever move forward
//
// The verifier, not the mirror, decides which commits are trustworthy.
//
// Staleness: Sync fetches at most every RefreshInterval. If a fetch fails the
// last good copy is used until it is older than MaxStaleness; after that Sync
// fails (the gate denies) unless AllowStale is set. Fail-closed is the
// default because a stale mirror can miss a key revocation.
package mirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hsouf/shipgate/internal/gitx"
)

// Mirror returns a local path to an up-to-date mirror of repo.
type Mirror interface {
	Sync(ctx context.Context, repo string) (path string, err error)
}

// NotImplemented always fails, so the gate fails closed.
type NotImplemented struct{}

func (NotImplemented) Sync(context.Context, string) (string, error) {
	return "", errors.New("repo mirror not configured")
}

// ForgeBranchPrefix is where the forge's (untrusted) branches are mirrored.
const ForgeBranchPrefix = "refs/remotes/forge/heads/"

// appendOnly are gittuf refs that must only move forward. A rewrite on the
// remote is a tampering signal; the mirror refuses to follow it.
var appendOnly = []string{
	"refs/gittuf/reference-state-log",
	"refs/gittuf/attestations",
	"refs/gittuf/policy",
}

const incoming = "refs/shipgate/incoming/"

// Config configures a Git mirror.
type Config struct {
	// Root is the directory that holds the mirrors.
	Root string
	// Repos maps repository IDs (as provenance reports them, e.g.
	// "github.com/acme/app") to clone URLs. Only these are mirrored.
	Repos map[string]string
	// RefreshInterval is the minimum time between fetches. Default 30s.
	RefreshInterval time.Duration
	// MaxStaleness is how old the last good fetch may be. Default 10m.
	MaxStaleness time.Duration
	// AllowStale keeps serving an older mirror when fetches keep failing.
	// Not recommended: a stale mirror can miss a key revocation.
	AllowStale bool
	// FetchTimeout bounds a single fetch. Default 20s.
	FetchTimeout time.Duration
}

// Git mirrors repositories with the git CLI.
type Git struct {
	cfg   Config
	now   func() time.Time
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// New returns a Git mirror with defaults applied.
func New(cfg Config) (*Git, error) {
	if cfg.Root == "" {
		return nil, errors.New("mirror: root directory is required")
	}
	if len(cfg.Repos) == 0 {
		return nil, errors.New("mirror: no repositories configured")
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Second
	}
	if cfg.MaxStaleness == 0 {
		cfg.MaxStaleness = 10 * time.Minute
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 20 * time.Second
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, err
	}
	return &Git{cfg: cfg, now: time.Now, locks: map[string]*sync.Mutex{}}, nil
}

// Repos returns the configured repository IDs, sorted.
func (m *Git) Repos() []string {
	ids := make([]string, 0, len(m.cfg.Repos))
	for id := range m.cfg.Repos {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Sync implements Mirror.
func (m *Git) Sync(ctx context.Context, repo string) (string, error) {
	url, ok := m.cfg.Repos[repo]
	if !ok {
		return "", fmt.Errorf("repository %q is not in the mirror allowlist", repo)
	}
	lock := m.lock(repo)
	lock.Lock()
	defer lock.Unlock()

	dir := m.dir(repo)
	last, _ := m.lastSync(dir)
	if !last.IsZero() && m.now().Sub(last) < m.cfg.RefreshInterval {
		return dir, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, m.cfg.FetchTimeout)
	defer cancel()
	err := m.fetch(fetchCtx, dir, url)
	if err == nil {
		return dir, m.markSynced(dir)
	}
	if last.IsZero() {
		return "", fmt.Errorf("mirror of %s has never synced: %w", repo, err)
	}
	age := m.now().Sub(last).Round(time.Second)
	if age <= m.cfg.MaxStaleness || m.cfg.AllowStale {
		return dir, nil
	}
	return "", fmt.Errorf("mirror of %s is stale (last good sync %s ago, limit %s): %w", repo, age, m.cfg.MaxStaleness, err)
}

// Refresh fetches every configured repository every interval until ctx is
// done, so request-time syncs rarely have to wait for the network. onErr is
// called for each failed fetch.
func (m *Git) Refresh(ctx context.Context, interval time.Duration, onErr func(repo string, err error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, repo := range m.Repos() {
			if _, err := m.Sync(ctx, repo); err != nil && onErr != nil {
				onErr(repo, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Git) lock(repo string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[repo]
	if !ok {
		l = &sync.Mutex{}
		m.locks[repo] = l
	}
	return l
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (m *Git) dir(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	name := strings.Trim(unsafeChars.ReplaceAllString(repo, "_"), "_.")
	return filepath.Join(m.cfg.Root, name+"-"+hex.EncodeToString(sum[:4])+".git")
}

const stampFile = "shipgate-last-sync"

func (m *Git) lastSync(dir string) (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(dir, stampFile))
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
}

func (m *Git) markSynced(dir string) error {
	tmp := filepath.Join(dir, stampFile+".tmp")
	if err := os.WriteFile(tmp, []byte(m.now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stampFile))
}

func (m *Git) fetch(ctx context.Context, dir, url string) error {
	g := &gitx.Repo{Dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if _, err := g.Output(ctx, "init", "--quiet", "--bare"); err != nil {
			return err
		}
	}
	// Fetch everything into staging namespaces first; nothing trusted moves
	// until the append-only check passes. The URL is passed on the command
	// line so a changed config can't redirect the mirror.
	if _, err := g.Output(ctx, "fetch", "--quiet", "--no-tags", "--prune", url,
		"+refs/heads/*:"+ForgeBranchPrefix+"*",
		"+refs/gittuf/*:"+incoming+"*"); err != nil {
		return err
	}
	return promoteGittufRefs(ctx, g)
}

// promoteGittufRefs copies refs/shipgate/incoming/* to refs/gittuf/*,
// refusing any non-fast-forward change to an append-only ref.
func promoteGittufRefs(ctx context.Context, g *gitx.Repo) error {
	out, err := g.Output(ctx, "for-each-ref", "--format=%(refname) %(objectname)", incoming)
	if err != nil {
		return err
	}
	type update struct{ ref, newID, oldID string }
	var updates []update
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		name, id, _ := strings.Cut(line, " ")
		ref := "refs/gittuf/" + strings.TrimPrefix(name, incoming)
		seen[ref] = true
		old, err := g.RefValue(ctx, ref)
		if err != nil {
			return err
		}
		if old == id {
			continue
		}
		if old != "" && isAppendOnly(ref) {
			if _, err := g.Output(ctx, "merge-base", "--is-ancestor", old, id); err != nil {
				return fmt.Errorf("remote rewrote %s (%.12s is not an ancestor of %.12s); refusing to follow, possible tampering", ref, old, id)
			}
		}
		updates = append(updates, update{ref, id, old})
	}
	for _, ref := range appendOnly {
		if old, _ := g.RefValue(ctx, ref); old != "" && !seen[ref] {
			return fmt.Errorf("remote deleted %s; refusing to follow, possible tampering", ref)
		}
	}
	for _, u := range updates {
		if err := g.SetRef(ctx, u.ref, u.newID, u.oldID); err != nil {
			return err
		}
	}
	return nil
}

func isAppendOnly(ref string) bool {
	for _, r := range appendOnly {
		if r == ref {
			return true
		}
	}
	return false
}
