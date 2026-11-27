package provenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// SLSA provenance predicate types accepted.
const (
	SLSAProvenanceV1  = "https://slsa.dev/provenance/v1"
	SLSAProvenanceV02 = "https://slsa.dev/provenance/v0.2"
)

// DefaultTriggers are the CI events that build from a branch's own history.
// pull_request_target is excluded on purpose: it runs the base branch's
// workflow, which can then build untrusted PR code.
var DefaultTriggers = []string{"push", "workflow_dispatch", "release", "schedule"}

// Policy decides which verified builder identities are trusted.
type Policy struct {
	// Repos are the repository IDs (e.g. github.com/acme/app) images may be
	// built from.
	Repos map[string]bool
	// Issuers are trusted OIDC issuers. Default: GitHub Actions.
	Issuers []string
	// Triggers are allowed build events. Default: DefaultTriggers.
	Triggers []string
	// AllowSelfHostedRunners accepts builds on self-hosted runners. Off by
	// default: a self-hosted runner is only as trustworthy as its host.
	AllowSelfHostedRunners bool
	// Signers are extra allowed signing workflows (regexps over the
	// certificate's Build Signer URI), for reusable workflows in other repos
	// such as the SLSA generator. Workflows in the source repo itself are
	// always allowed, but must come from the commit being built.
	Signers []*regexp.Regexp
}

func (p Policy) issuers() []string {
	if len(p.Issuers) == 0 {
		return []string{GitHubActionsIssuer}
	}
	return p.Issuers
}

func (p Policy) triggers() []string {
	if len(p.Triggers) == 0 {
		return DefaultTriggers
	}
	return p.Triggers
}

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Evaluate applies the policy to a verified attestation.
func (p Policy) Evaluate(a *Attestation) (Source, error) {
	id := a.Identity
	if !contains(p.issuers(), id.Issuer) {
		return Source{}, fmt.Errorf("signed by untrusted OIDC issuer %q", id.Issuer)
	}
	repo, ok := repoID(id.SourceRepoURI)
	if !ok {
		return Source{}, fmt.Errorf("certificate has no usable source repository (%q)", id.SourceRepoURI)
	}
	trusted := ""
	for r := range p.Repos {
		if strings.EqualFold(r, repo) {
			trusted = r
		}
	}
	if trusted == "" {
		return Source{}, fmt.Errorf("built from %s, which is not a trusted repository", repo)
	}
	repo = trusted
	if !fullSHA.MatchString(id.SourceRepoDigest) {
		return Source{}, fmt.Errorf("certificate has no source commit (%q)", id.SourceRepoDigest)
	}
	if id.RunnerEnv == "" || (id.RunnerEnv == "self-hosted" && !p.AllowSelfHostedRunners) {
		return Source{}, fmt.Errorf("built on a %q runner; only hosted runners are trusted", orUnknown(id.RunnerEnv))
	}
	if !contains(p.triggers(), id.Trigger) {
		return Source{}, fmt.Errorf("built by a %q event, not one of %s", orUnknown(id.Trigger), strings.Join(p.triggers(), ", "))
	}
	if err := p.checkSigner(id); err != nil {
		return Source{}, err
	}
	if a.PredicateType != SLSAProvenanceV1 && a.PredicateType != SLSAProvenanceV02 {
		return Source{}, fmt.Errorf("not SLSA provenance (predicate %q)", a.PredicateType)
	}
	if err := checkPredicateCommit(a, id); err != nil {
		return Source{}, err
	}
	return Source{Repo: repo, Commit: id.SourceRepoDigest, Builder: id.SignerURI}, nil
}

func (p Policy) checkSigner(id Identity) error {
	if strings.HasPrefix(id.SignerURI, id.SourceRepoURI+"/") {
		// A workflow from the repo itself must come from the commit being
		// built, so the workflow that ran is the one that was approved.
		if id.SignerDigest != id.SourceRepoDigest {
			return fmt.Errorf("signing workflow is from commit %.12s, not the built commit %.12s", id.SignerDigest, id.SourceRepoDigest)
		}
		return nil
	}
	for _, re := range p.Signers {
		if re.MatchString(id.SignerURI) {
			return nil
		}
	}
	return fmt.Errorf("signed by workflow %q, which is not in the source repository or the allowed signers", id.SignerURI)
}

// checkPredicateCommit rejects predicates that name a different commit of the
// source repository than the certificate does.
func checkPredicateCommit(a *Attestation, id Identity) error {
	var pred struct {
		BuildDefinition struct {
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		Materials []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"materials"`
	}
	if err := json.Unmarshal(a.Predicate, &pred); err != nil {
		return fmt.Errorf("unreadable SLSA predicate: %w", err)
	}
	type dep struct {
		uri    string
		digest map[string]string
	}
	var deps []dep
	for _, d := range pred.BuildDefinition.ResolvedDependencies {
		deps = append(deps, dep{d.URI, d.Digest})
	}
	for _, d := range pred.Materials {
		deps = append(deps, dep{d.URI, d.Digest})
	}
	want := "git+" + id.SourceRepoURI
	for _, d := range deps {
		uri, _, _ := strings.Cut(d.uri, "@")
		if !strings.EqualFold(strings.TrimSuffix(uri, ".git"), want) {
			continue
		}
		for _, k := range []string{"gitCommit", "sha1"} {
			if c := d.digest[k]; c != "" && c != id.SourceRepoDigest {
				return errors.New("provenance predicate names a different source commit than the signing certificate")
			}
		}
	}
	return nil
}

// repoID turns https://github.com/acme/app into github.com/acme/app.
func repoID(uri string) (string, bool) {
	rest, ok := strings.CutPrefix(uri, "https://")
	rest = strings.TrimSuffix(rest, ".git")
	if !ok || !strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v && v != "" {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
