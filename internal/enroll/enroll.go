// Package enroll provisions a hardware-backed signing key and configures git
// to sign every commit with it.
//
// Status: key generation and git config are implemented (#5).
// TODO(#6): verify the FIDO attestation written at keygen against an
// allowlist of authenticator models so software-only keys are rejected.
// TODO(#7): produce a staged gittuf policy change registering the person.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Options controls enrollment.
type Options struct {
	KeyPath string
	Comment string
	Global  bool
	DryRun  bool
	Out     io.Writer
}

// Command is a single external command enrollment will run.
type Command struct {
	Name string
	Args []string
}

func (c Command) String() string {
	return c.Name + " " + strings.Join(c.Args, " ")
}

// Plan returns the commands needed to enroll, without running them.
func Plan(opts Options) ([]Command, error) {
	keyPath, err := resolveKeyPath(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	keygen := []string{
		"-t", "ed25519-sk",
		// Require PIN (user verification) on every signature, not just touch.
		"-O", "verify-required",
		// Keep the FIDO attestation so #6 can prove the key is real hardware.
		"-O", "write-attestation=" + keyPath + ".attestation",
		"-f", keyPath,
	}
	if opts.Comment != "" {
		keygen = append(keygen, "-C", opts.Comment)
	}

	scope := "--local"
	if opts.Global {
		scope = "--global"
	}
	gitcfg := func(k, v string) Command {
		return Command{Name: "git", Args: []string{"config", scope, k, v}}
	}

	return []Command{
		{Name: "ssh-keygen", Args: keygen},
		gitcfg("gpg.format", "ssh"),
		gitcfg("user.signingkey", keyPath+".pub"),
		gitcfg("commit.gpgsign", "true"),
		gitcfg("tag.gpgsign", "true"),
	}, nil
}

// Run executes the enrollment plan, or prints it with DryRun.
func Run(ctx context.Context, opts Options) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	cmds, err := Plan(opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		for _, c := range cmds {
			fmt.Fprintln(opts.Out, c.String())
		}
		return nil
	}
	if _, err := os.Stat(cmds[0].Args[len(cmds[0].Args)-1]); err == nil {
		// Never overwrite an existing key silently.
		return errors.New("key already exists at the target path; pass --key-path to choose another")
	}
	for _, c := range cmds {
		fmt.Fprintf(opts.Out, "running: %s\n", c)
		cmd := exec.CommandContext(ctx, c.Name, c.Args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, opts.Out, opts.Out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
	}
	fmt.Fprintln(opts.Out, "enrolled. Next: ask a root key holder to approve your policy registration (see #7).")
	return nil
}

func resolveKeyPath(p string) (string, error) {
	if p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "id_ed25519_sk_shipgate"), nil
}
