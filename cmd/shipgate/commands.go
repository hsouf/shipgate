package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hsouf/shipgate/internal/approve"
	"github.com/hsouf/shipgate/internal/audit"
	"github.com/hsouf/shipgate/internal/change"
	"github.com/hsouf/shipgate/internal/enroll"
	"github.com/hsouf/shipgate/internal/gate"
	"github.com/hsouf/shipgate/internal/gittufx"
	"github.com/hsouf/shipgate/internal/gitx"
	"github.com/hsouf/shipgate/internal/merge"
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

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "image reference pinned by digest (repo@sha256:...)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if strings.TrimSpace(*image) == "" {
		fmt.Fprintln(stderr, "--image is required")
		return errUsage
	}
	d := gate.NewVerifier(gate.Config{}).Verify(ctx, gate.Request{Image: *image})
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
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	srv := webhook.NewServer(cfg, gate.NewVerifier(gate.Config{}), audit.NewLogger(stderr))
	return srv.ListenAndServe(ctx)
}
