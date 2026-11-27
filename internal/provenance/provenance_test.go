package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	repoURI = "https://github.com/acme/app"
	commit  = "0123456789abcdef0123456789abcdef01234567"
)

var policy = Policy{Repos: map[string]bool{"github.com/acme/app": true}}

func goodAttestation() *Attestation {
	pred, _ := json.Marshal(map[string]any{
		"buildDefinition": map[string]any{
			"resolvedDependencies": []any{map[string]any{
				"uri":    "git+" + repoURI + "@refs/heads/main",
				"digest": map[string]string{"gitCommit": commit},
			}},
		},
	})
	return &Attestation{
		Identity: Identity{
			Issuer:           GitHubActionsIssuer,
			SourceRepoURI:    repoURI,
			SourceRepoDigest: commit,
			SourceRepoRef:    "refs/heads/main",
			SignerURI:        repoURI + "/.github/workflows/release.yml@refs/heads/main",
			SignerDigest:     commit,
			Trigger:          "push",
			RunnerEnv:        "github-hosted",
		},
		PredicateType: SLSAProvenanceV1,
		Predicate:     pred,
	}
}

func TestPolicyAcceptsHostedBuildOfTrustedRepo(t *testing.T) {
	src, err := policy.Evaluate(goodAttestation())
	if err != nil {
		t.Fatal(err)
	}
	if src.Repo != "github.com/acme/app" || src.Commit != commit || !strings.Contains(src.Builder, "release.yml") {
		t.Errorf("source = %+v", src)
	}
}

func TestPolicyDenies(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(a *Attestation)
		want string
	}{
		"untrusted issuer":    {func(a *Attestation) { a.Identity.Issuer = "https://evil.example" }, "untrusted OIDC issuer"},
		"untrusted repo":      {func(a *Attestation) { a.Identity.SourceRepoURI = "https://github.com/evil/app" }, "not a trusted repository"},
		"no commit":           {func(a *Attestation) { a.Identity.SourceRepoDigest = "" }, "no source commit"},
		"self-hosted runner":  {func(a *Attestation) { a.Identity.RunnerEnv = "self-hosted" }, "hosted runners"},
		"unknown runner":      {func(a *Attestation) { a.Identity.RunnerEnv = "" }, "hosted runners"},
		"pull_request_target": {func(a *Attestation) { a.Identity.Trigger = "pull_request_target" }, "event"},
		"workflow from elsewhere": {func(a *Attestation) {
			a.Identity.SignerURI = "https://github.com/evil/wf/.github/workflows/x.yml@refs/heads/main"
		}, "not in the source repository"},
		"workflow from another commit": {func(a *Attestation) {
			a.Identity.SignerDigest = strings.Repeat("f", 40)
		}, "signing workflow is from commit"},
		"not provenance": {func(a *Attestation) { a.PredicateType = "https://spdx.dev/Document" }, "not SLSA provenance"},
		"predicate names other commit": {func(a *Attestation) {
			a.Predicate = []byte(`{"buildDefinition":{"resolvedDependencies":[{"uri":"git+https://github.com/acme/app@refs/heads/main","digest":{"gitCommit":"` + strings.Repeat("e", 40) + `"}}]}}`)
		}, "different source commit"},
	} {
		t.Run(name, func(t *testing.T) {
			a := goodAttestation()
			tc.mod(a)
			_, err := policy.Evaluate(a)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPolicyAllowsConfiguredReusableWorkflow(t *testing.T) {
	a := goodAttestation()
	a.Identity.SignerURI = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
	a.Identity.SignerDigest = strings.Repeat("b", 40)
	p := policy
	if _, err := p.Evaluate(a); err == nil {
		t.Fatal("reusable workflow accepted without being configured")
	}
	p.Signers = []*regexp.Regexp{regexp.MustCompile(`^https://github\.com/slsa-framework/slsa-github-generator/\.github/workflows/generator_container_slsa3\.yml@refs/tags/v2\.`)}
	if _, err := p.Evaluate(a); err != nil {
		t.Fatalf("configured reusable workflow denied: %v", err)
	}
}

func TestPolicyOptIns(t *testing.T) {
	a := goodAttestation()
	a.Identity.RunnerEnv = "self-hosted"
	p := policy
	p.AllowSelfHostedRunners = true
	if _, err := p.Evaluate(a); err != nil {
		t.Errorf("self-hosted opt-in: %v", err)
	}
	a = goodAttestation()
	a.Identity.Trigger = "merge_group"
	p = policy
	p.Triggers = []string{"merge_group"}
	if _, err := p.Evaluate(a); err != nil {
		t.Errorf("trigger opt-in: %v", err)
	}
}

type fakeSource struct {
	bundles [][]byte
	err     error
}

func (f fakeSource) Bundles(context.Context, string) ([][]byte, error) { return f.bundles, f.err }

// fakeBundles "verifies" bundles whose content is "ok" or "bad".
type fakeBundles struct{}

func (fakeBundles) VerifyBundle(_ context.Context, b []byte, alg string, d []byte) (*Attestation, error) {
	if alg != "sha256" || len(d) != 32 {
		return nil, errors.New("wrong digest passed")
	}
	switch string(b) {
	case "ok":
		return goodAttestation(), nil
	case "self-hosted":
		a := goodAttestation()
		a.Identity.RunnerEnv = "self-hosted"
		return a, nil
	}
	return nil, errors.New("signature invalid")
}

const image = "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSigstoreVerifier(t *testing.T) {
	ctx := context.Background()
	v := func(src BundleSource) *Sigstore {
		return &Sigstore{Source: src, Bundles: fakeBundles{}, Policy: policy}
	}

	if src, err := v(fakeSource{bundles: [][]byte{[]byte("bad"), []byte("ok")}}).Verify(ctx, image); err != nil || src.Commit != commit {
		t.Fatalf("one good bundle among bad: %+v %v", src, err)
	}
	for name, tc := range map[string]struct {
		src   BundleSource
		image string
		want  string
	}{
		"no bundles":     {fakeSource{}, image, "no Sigstore provenance"},
		"fetch error":    {fakeSource{err: errors.New("registry down")}, image, "registry down"},
		"all invalid":    {fakeSource{bundles: [][]byte{[]byte("bad"), []byte("self-hosted")}}, image, "signature invalid; built on a \"self-hosted\""},
		"tag not digest": {fakeSource{bundles: [][]byte{[]byte("ok")}}, "ghcr.io/acme/app:latest", "not pinned"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v(tc.src).Verify(ctx, tc.image)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRealGitHubActionsBundle verifies a real bundle signed by GitHub Actions
// (sigstore-js 1.3.0 npm provenance, from sigstore-go's examples) against the
// public-good trusted root, offline.
func TestRealGitHubActionsBundle(t *testing.T) {
	raw, err := os.ReadFile("testdata/sigstore-js-1.3.0.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		DSSE struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(b.DSSE.Payload)
	var st struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(st.Subject[0].Digest["sha512"])

	sb := &SigstoreBundles{Trusted: TrustedRootFromFile("testdata/trusted-root-public-good.json")}
	ctx := context.Background()
	att, err := sb.VerifyBundle(ctx, raw, "sha512", digest)
	if err != nil {
		t.Fatalf("real bundle does not verify: %v", err)
	}
	id := att.Identity
	if id.Issuer != GitHubActionsIssuer || id.SourceRepoURI != "https://github.com/sigstore/sigstore-js" ||
		len(id.SourceRepoDigest) != 40 || id.Trigger != "push" || id.RunnerEnv != "github-hosted" {
		t.Fatalf("identity = %+v", id)
	}
	p := Policy{Repos: map[string]bool{"github.com/sigstore/sigstore-js": true}}
	src, err := p.Evaluate(att)
	if err != nil {
		t.Fatalf("policy rejected a genuine hosted release build: %v", err)
	}
	if src.Commit != id.SourceRepoDigest {
		t.Errorf("commit %s", src.Commit)
	}

	// Same bundle, wrong artifact: must not verify.
	other := append([]byte(nil), digest...)
	other[0] ^= 0xff
	if _, err := sb.VerifyBundle(ctx, raw, "sha512", other); err == nil {
		t.Error("bundle verified for a different artifact")
	}
	// Same bundle, repo not trusted.
	if _, err := policy.Evaluate(att); err == nil {
		t.Error("untrusted repo accepted")
	}
	// Tampered bundle.
	bad := []byte(strings.Replace(string(raw), b.DSSE.Payload[:20], "AAAAAAAAAAAAAAAAAAAA", 1))
	if _, err := sb.VerifyBundle(ctx, bad, "sha512", digest); err == nil {
		t.Error("tampered bundle verified")
	}
}
