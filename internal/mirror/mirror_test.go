package mirror

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const repoID = "github.com/acme/app"
const rsl = "refs/gittuf/reference-state-log"

type remote struct {
	t   *testing.T
	dir string
}

func newRemote(t *testing.T) *remote {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r := &remote{t: t, dir: filepath.Join(t.TempDir(), "remote")}
	r.git("init", "-q", "-b", "main", r.dir)
	r.git("-C", r.dir, "config", "user.name", "t")
	r.git("-C", r.dir, "config", "user.email", "t@example.com")
	r.commit("refs/heads/main", "first")
	r.commit(rsl, "rsl 1")
	return r
}

func (r *remote) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit appends an empty commit to ref.
func (r *remote) commit(ref, msg string) string {
	r.t.Helper()
	tree := r.git("-C", r.dir, "hash-object", "-t", "tree", "-w", "/dev/null")
	args := []string{"-C", r.dir, "commit-tree", tree, "-m", msg}
	if parent := r.rev(ref); parent != "" {
		args = append(args, "-p", parent)
	}
	c := r.git(args...)
	r.git("-C", r.dir, "update-ref", ref, c)
	return c
}

func (r *remote) rev(ref string) string {
	cmd := exec.Command("git", "-C", r.dir, "rev-parse", "--verify", "--quiet", ref)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newMirror(t *testing.T, r *remote, mod func(*Config)) (*Git, *clock) {
	cfg := Config{Root: t.TempDir(), Repos: map[string]string{repoID: r.dir}}
	if mod != nil {
		mod(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}
	m.now = c.now
	return m, c
}

func refIn(t *testing.T, dir, ref string) string {
	t.Helper()
	out, _ := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", ref).Output()
	return strings.TrimSpace(string(out))
}

func TestSyncMirrorsBranchesAndGittufRefs(t *testing.T) {
	r := newRemote(t)
	m, _ := newMirror(t, r, nil)
	dir, err := m.Sync(context.Background(), repoID)
	if err != nil {
		t.Fatal(err)
	}
	if got := refIn(t, dir, ForgeBranchPrefix+"main"); got != r.rev("refs/heads/main") {
		t.Errorf("forge main = %q", got)
	}
	if got := refIn(t, dir, rsl); got != r.rev(rsl) {
		t.Errorf("RSL = %q", got)
	}
	if got := refIn(t, dir, "refs/heads/main"); got != "" {
		t.Error("mirror must not create trusted branches from the forge's view")
	}
}

func TestSyncDeniesRepoNotInAllowlist(t *testing.T) {
	m, _ := newMirror(t, newRemote(t), nil)
	if _, err := m.Sync(context.Background(), "github.com/evil/app"); err == nil {
		t.Fatal("synced a repository that is not configured")
	}
}

func TestSyncRefusesRSLRewrite(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, func(cfg *Config) { cfg.MaxStaleness = time.Minute })
	ctx := context.Background()
	dir, err := m.Sync(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	good := refIn(t, dir, rsl)

	// Attacker with forge admin rewrites the RSL.
	r.git("-C", r.dir, "update-ref", "-d", rsl)
	r.commit(rsl, "forged history")
	c.t = c.t.Add(2 * time.Minute)

	_, err = m.Sync(ctx, repoID)
	if err == nil || !strings.Contains(err.Error(), "rewrote") {
		t.Fatalf("err = %v, want rewrite refused", err)
	}
	if got := refIn(t, dir, rsl); got != good {
		t.Error("mirror followed a rewritten RSL")
	}
}

func TestSyncRefusesRSLDeletion(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, func(cfg *Config) { cfg.MaxStaleness = time.Minute })
	ctx := context.Background()
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	r.git("-C", r.dir, "update-ref", "-d", rsl)
	c.t = c.t.Add(2 * time.Minute)
	if _, err := m.Sync(ctx, repoID); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("err = %v, want deletion refused", err)
	}
}

func TestSyncFollowsAppendedRSL(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, nil)
	ctx := context.Background()
	dir, _ := m.Sync(ctx, repoID)
	next := r.commit(rsl, "rsl 2")
	c.t = c.t.Add(time.Minute)
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	if refIn(t, dir, rsl) != next {
		t.Error("appended RSL entry not mirrored")
	}
}

func TestSyncRespectsRefreshInterval(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, func(cfg *Config) { cfg.RefreshInterval = time.Minute })
	ctx := context.Background()
	dir, _ := m.Sync(ctx, repoID)
	before := refIn(t, dir, rsl)
	r.commit(rsl, "rsl 2")
	c.t = c.t.Add(30 * time.Second)
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	if refIn(t, dir, rsl) != before {
		t.Error("fetched before the refresh interval elapsed")
	}
}

func TestStalenessFailsClosed(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, func(cfg *Config) { cfg.MaxStaleness = 10 * time.Minute })
	ctx := context.Background()
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(r.dir); err != nil { // forge unreachable
		t.Fatal(err)
	}

	c.t = c.t.Add(5 * time.Minute)
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatalf("within staleness bound the last good mirror must be used: %v", err)
	}
	c.t = c.t.Add(10 * time.Minute)
	if _, err := m.Sync(ctx, repoID); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("err = %v, want stale deny", err)
	}
}

func TestAllowStaleServesOldMirror(t *testing.T) {
	r := newRemote(t)
	m, c := newMirror(t, r, func(cfg *Config) { cfg.AllowStale = true })
	ctx := context.Background()
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(r.dir)
	c.t = c.t.Add(24 * time.Hour)
	if _, err := m.Sync(ctx, repoID); err != nil {
		t.Fatalf("AllowStale: %v", err)
	}
}

func TestNeverSyncedFailsClosed(t *testing.T) {
	r := newRemote(t)
	m, _ := newMirror(t, r, func(cfg *Config) { cfg.AllowStale = true })
	os.RemoveAll(r.dir)
	if _, err := m.Sync(context.Background(), repoID); err == nil {
		t.Fatal("a mirror that never synced must deny, even with AllowStale")
	}
}
