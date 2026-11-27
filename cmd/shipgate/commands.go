package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hsouf/shipgate/internal/approve"
	"github.com/hsouf/shipgate/internal/audit"
	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/enroll"
	"github.com/hsouf/shipgate/internal/gate"
	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/gitx"
	"github.com/hsouf/shipgate/internal/merge"
	"github.com/hsouf/shipgate/internal/mirror"
	"github.com/hsouf/shipgate/internal/provenance"
	"github.com/hsouf/shipgate/internal/rslcheck"
	"github.com/hsouf/shipgate/internal/version"
	"github.com/hsouf/shipgate/internal/webhook"
)

var errUsage = errors.New("usage")

type command struct {
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

var commands = map[string]command{
	"version":       {"Print version information", runVersion},
	"enroll":        {"Generate a hardware-backed signing key and configure git (#5-#7)", runEnroll},
	"init":          {"Bootstrap gittuf root of trust and the default policy pack (#8, #9)", notImplemented("#8")},
	"approve":       {"Hardware-signed approval bound to the exact tree (#10, #11)", runApprove},
	"merge":         {"Merge locally, sign, record RSL entry and push (#12)", runMerge},
	"verify":        {"Decide whether an image may be deployed (#13-#15)", runVerify},
	"webhook-serve": {"Serve the Kubernetes admission webhook, audit-only by default (#16, #17)", runWebhookServe},
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(os.Stderr)
		return errUsage
	}
	c, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return errUsage
	}
	return c.run(ctx, args[1:], os.Stdout, os.Stderr)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "shipgate: a stolen GitHub account shouldn't be able to ship to production")
	fmt.Fprintln(w, "\nUsage: shipgate <command> [flags]\n\nCommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-14s %s\n", n, commands[n].summary)
	}
	fmt.Fprintln(w, "\nRun 'shipgate <command> -h' for command flags.")
}

func notImplemented(issue string) func(context.Context, []string, io.Writer, io.Writer) error {
	return func(context.Context, []string, io.Writer, io.Writer) error {
		return fmt.Errorf("not implemented yet: see %s in docs/issues.md", issue)
	}
}

func runVersion(_ context.Context, _ []string, stdout, _ io.Writer) error {
	fmt.Fprintf(stdout, "shipgate %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
	return nil
}

func runEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts enroll.Options
	fs.StringVar(&opts.KeyPath, "key-path", "", "path for the new key (default ~/.ssh/id_ed25519_sk_shipgate)")
	fs.StringVar(&opts.Comment, "comment", "", "key comment, usually your email")
	fs.BoolVar(&opts.Global, "global", true, "write git config globally instead of for the current repo")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print the commands without running them")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	opts.Out = stdout
	return enroll.Run(ctx, opts)
}

// branchCommand parses "<branch> [--into main] [--remote origin]", with flags
// accepted before or after the branch.
func branchCommand(name string, args []string, stdout, stderr io.Writer) (branch, into string, env change.Env, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: shipgate %s [flags] <branch>\n\nFlags:\n", name)
		fs.PrintDefaults()
	}
	intoFlag := fs.String("into", "main", "protected branch the change merges into")
	remote := fs.String("remote", "origin", "git remote to sync with and push to")
	if err := fs.Parse(args); err != nil {
		return "", "", env, errUsage
	}
	rest := fs.Args()
	if len(rest) > 0 {
		branch = rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return "", "", env, errUsage
		}
		rest = fs.Args()
	}
	if branch == "" || len(rest) > 0 {
		fs.Usage()
		return "", "", env, errUsage
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", "", env, err
	}
	env = change.Env{
		Git:      &gitx.Repo{Dir: dir, Stderr: stderr},
		Gittuf:   &gittufx.CLI{Dir: dir, Stderr: stderr},
		Verifier: change.HardwareVerifier{},
		Remote:   *remote,
		Out:      stdout,
	}
	return branch, *intoFlag, env, nil
}

func runApprove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	branch, into, env, err := branchCommand("approve", args, stdout, stderr)
	if err != nil {
		return err
	}
	return approve.Run(ctx, approve.Options{Feature: branch, Target: into, Env: env})
}

func runMerge(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	branch, into, env, err := branchCommand("merge", args, stdout, stderr)
	if err != nil {
		return err
	}
	return merge.Run(ctx, merge.Options{Feature: branch, Target: into, Env: env})
}

// gateFlags are the deploy-gate settings shared by verify and webhook-serve.
type gateFlags struct {
	repos         repoList
	mirrorDir     string
	protectedRefs string
	maxStaleness  time.Duration
	refresh       time.Duration
	allowStale    bool
	gittuf        string

	// provenance (#13)
	bundles       stringList
	trustedRoot   string
	sigstoreCache string
	noTlog        bool
	issuers       stringList
	triggers      string
	signers       stringList
	selfHosted    bool
}

func (g *gateFlags) register(fs *flag.FlagSet) {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	fs.Var(&g.repos, "repo", "source repository to trust, as ID or ID=URL (e.g. github.com/acme/app); repeatable")
	fs.StringVar(&g.mirrorDir, "mirror-dir", filepath.Join(cache, "shipgate", "mirrors"), "directory for repository mirrors")
	fs.StringVar(&g.protectedRefs, "protected-ref", "refs/heads/main", "comma-separated refs a deployable commit must be verified on")
	fs.DurationVar(&g.maxStaleness, "mirror-max-staleness", 10*time.Minute, "deny when the last good mirror sync is older than this")
	fs.DurationVar(&g.refresh, "mirror-refresh", 30*time.Second, "minimum time between mirror fetches")
	fs.BoolVar(&g.allowStale, "allow-stale-mirror", false, "keep using a stale mirror when the forge is unreachable (not recommended)")
	fs.StringVar(&g.gittuf, "gittuf", "", "path to the gittuf binary (default: look up in PATH)")

	fs.StringVar(&g.trustedRoot, "sigstore-trusted-root", "", "Sigstore trusted_root.json (default: public-good instance via TUF)")
	fs.StringVar(&g.sigstoreCache, "sigstore-cache-dir", filepath.Join(cache, "shipgate", "sigstore"), "cache for the Sigstore TUF metadata")
	fs.BoolVar(&g.noTlog, "sigstore-no-tlog", false, "accept bundles without transparency log entries (private Sigstore instances, e.g. GitHub private repos)")
	fs.Var(&g.issuers, "builder-issuer", "trusted CI OIDC issuer; repeatable (default: GitHub Actions)")
	fs.StringVar(&g.triggers, "builder-triggers", strings.Join(provenance.DefaultTriggers, ","), "comma-separated CI events allowed to build deployable images")
	fs.Var(&g.signers, "builder-signer", "regexp for an extra allowed signing workflow (e.g. a reusable workflow in another repo); repeatable")
	fs.BoolVar(&g.selfHosted, "allow-self-hosted-runners", false, "accept builds from self-hosted CI runners")
}

func (g *gateFlags) provenance() (provenance.Verifier, error) {
	trusted := provenance.PublicGoodTrustedRoot(g.sigstoreCache)
	if g.trustedRoot != "" {
		trusted = provenance.TrustedRootFromFile(g.trustedRoot)
	}
	pol := provenance.Policy{Repos: map[string]bool{}, Issuers: g.issuers, AllowSelfHostedRunners: g.selfHosted}
	for id := range g.repos {
		pol.Repos[id] = true
	}
	for _, t := range strings.Split(g.triggers, ",") {
		if t = strings.TrimSpace(t); t != "" {
			pol.Triggers = append(pol.Triggers, t)
		}
	}
	for _, expr := range g.signers {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("--builder-signer %q: %w", expr, err)
		}
		pol.Signers = append(pol.Signers, re)
	}
	var src provenance.BundleSource = provenance.Registry{}
	if len(g.bundles) > 0 {
		src = provenance.Files(g.bundles)
	}
	return &provenance.Sigstore{
		Source:  src,
		Bundles: &provenance.SigstoreBundles{Trusted: trusted, Issuers: g.issuers, NoTransparencyLog: g.noTlog},
		Policy:  pol,
	}, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// config builds the gate configuration. Without --repo the mirror is not
// configured and every request is denied.
func (g *gateFlags) config() (gate.Config, *mirror.Git, error) {
	cfg := gate.Config{
		Policy: &rslcheck.Verifier{
			Gittuf:     rslcheck.GittufCLI{Bin: g.gittuf},
			Signatures: change.HardwareVerifier{},
		},
	}
	for _, r := range strings.Split(g.protectedRefs, ",") {
		if r = strings.TrimSpace(r); r != "" {
			cfg.ProtectedRefs = append(cfg.ProtectedRefs, r)
		}
	}
	if len(g.repos) == 0 {
		return cfg, nil, nil
	}
	prov, err := g.provenance()
	if err != nil {
		return cfg, nil, err
	}
	cfg.Provenance = prov
	m, err := mirror.New(mirror.Config{
		Root:            g.mirrorDir,
		Repos:           map[string]string(g.repos),
		RefreshInterval: g.refresh,
		MaxStaleness:    g.maxStaleness,
		AllowStale:      g.allowStale,
	})
	if err != nil {
		return cfg, nil, err
	}
	cfg.Mirror = m
	return cfg, m, nil
}

// repoList parses repeated --repo ID[=URL] flags. Without a URL, ID is
// cloned over HTTPS (https://ID.git).
type repoList map[string]string

func (r *repoList) String() string { return fmt.Sprint(map[string]string(*r)) }

func (r *repoList) Set(v string) error {
	id, url, hasURL := strings.Cut(v, "=")
	id = strings.TrimSuffix(strings.TrimSpace(id), ".git")
	if id == "" || strings.Contains(id, "://") {
		return fmt.Errorf("invalid repo %q: want ID or ID=URL, e.g. github.com/acme/app", v)
	}
	if !hasURL {
		url = "https://" + id + ".git"
	}
	if *r == nil {
		*r = repoList{}
	}
	(*r)[id] = url
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "image reference pinned by digest (repo@sha256:...)")
	commit := fs.String("commit", "", "verify a source commit (full SHA) instead of an image; requires exactly one --repo")
	var gf gateFlags
	gf.register(fs)
	fs.Var(&gf.bundles, "provenance-bundle", "read provenance from this Sigstore bundle file instead of the registry; repeatable")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	hasImage, hasCommit := strings.TrimSpace(*image) != "", strings.TrimSpace(*commit) != ""
	if hasImage == hasCommit {
		fmt.Fprintln(stderr, "pass either --image, or --commit with --repo")
		return errUsage
	}
	if hasCommit && len(gf.repos) != 1 {
		fmt.Fprintln(stderr, "--commit needs exactly one --repo")
		return errUsage
	}
	cfg, _, err := gf.config()
	if err != nil {
		return err
	}
	v := gate.NewVerifier(cfg)
	var d gate.Decision
	if hasCommit {
		var repo string
		for id := range gf.repos {
			repo = id
		}
		d = v.VerifyCommit(ctx, repo, strings.TrimSpace(*commit))
	} else {
		d = v.Verify(ctx, gate.Request{Image: *image})
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return err
	}
	if !d.Allowed {
		return gate.ErrDenied
	}
	return nil
}

func runWebhookServe(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("webhook-serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg webhook.Config
	fs.StringVar(&cfg.Addr, "addr", ":8443", "listen address")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file (required by Kubernetes)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS key file")
	fs.BoolVar(&cfg.Enforce, "enforce", false, "deny requests that fail verification (default: audit only)")
	var gf gateFlags
	gf.register(fs)
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	gcfg, m, err := gf.config()
	if err != nil {
		return err
	}
	logger := audit.NewLogger(stderr)
	if m != nil {
		// Refresh twice per interval so request-time syncs find a fresh
		// mirror and don't wait on the network.
		go m.Refresh(ctx, gf.refresh/2, func(repo string, err error) {
			fmt.Fprintf(stderr, "shipgate: mirror sync %s: %v\n", repo, err)
		})
	} else {
		fmt.Fprintln(stderr, "shipgate: no --repo configured; every image will be denied")
	}
	srv := webhook.NewServer(cfg, gate.NewVerifier(gcfg), logger)
	return srv.ListenAndServe(ctx)
}
