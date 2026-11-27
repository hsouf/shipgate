package provenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// SigstoreBundles verifies bundles with sigstore-go.
type SigstoreBundles struct {
	// Trusted returns Sigstore's trusted material (Fulcio CAs, Rekor and CT
	// logs, timestamp authorities).
	Trusted func(ctx context.Context) (root.TrustedMaterial, error)
	// Issuers restricts the certificate's OIDC issuer; it is checked again
	// by Policy. Empty means GitHub Actions.
	Issuers []string
	// NoTransparencyLog accepts bundles without Rekor entries and SCTs, for
	// Sigstore instances that use a timestamp authority instead (GitHub's
	// instance for private repositories). The public-good instance needs both.
	NoTransparencyLog bool
}

// VerifyBundle implements BundleVerifier.
func (s *SigstoreBundles) VerifyBundle(ctx context.Context, bundleJSON []byte, digestAlg string, digest []byte) (*Attestation, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("invalid Sigstore bundle: %w", err)
	}
	trusted, err := s.Trusted(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading Sigstore trusted root: %w", err)
	}
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if !s.NoTransparencyLog {
		opts = append(opts, verify.WithTransparencyLog(1), verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(trusted, opts...)
	if err != nil {
		return nil, err
	}
	issuers := s.Issuers
	if len(issuers) == 0 {
		issuers = []string{GitHubActionsIssuer}
	}
	quoted := make([]string, len(issuers))
	for i, is := range issuers {
		quoted[i] = regexp.QuoteMeta(is)
	}
	id, err := verify.NewShortCertificateIdentity("", "^("+strings.Join(quoted, "|")+")$", "", ".+")
	if err != nil {
		return nil, err
	}
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest(digestAlg, digest), verify.WithCertificateIdentity(id)))
	if err != nil {
		return nil, fmt.Errorf("bundle does not verify: %w", err)
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return nil, errors.New("bundle is not signed with a Fulcio certificate")
	}
	if res.Statement == nil {
		return nil, errors.New("bundle has no in-toto statement")
	}
	pred, err := protojson.Marshal(res.Statement.GetPredicate())
	if err != nil {
		return nil, err
	}
	c := res.Signature.Certificate
	return &Attestation{
		Identity: Identity{
			Issuer:           c.Issuer,
			SourceRepoURI:    c.SourceRepositoryURI,
			SourceRepoDigest: c.SourceRepositoryDigest,
			SourceRepoRef:    c.SourceRepositoryRef,
			SignerURI:        c.BuildSignerURI,
			SignerDigest:     c.BuildSignerDigest,
			Trigger:          c.BuildTrigger,
			RunnerEnv:        c.RunnerEnvironment,
		},
		PredicateType: res.Statement.GetPredicateType(),
		Predicate:     pred,
	}, nil
}

// TrustedRootFromFile loads a trusted_root.json, e.g. for an offline cluster
// or a private Sigstore instance.
func TrustedRootFromFile(path string) func(context.Context) (root.TrustedMaterial, error) {
	var once sync.Once
	var tr root.TrustedMaterial
	var err error
	return func(context.Context) (root.TrustedMaterial, error) {
		once.Do(func() { tr, err = root.NewTrustedRootFromPath(path) })
		return tr, err
	}
}

// PublicGoodTrustedRoot fetches Sigstore's public-good trusted root over TUF
// and keeps it refreshed. A failed fetch is retried on the next call (and the
// image denied meanwhile), so a network blip at startup isn't permanent.
func PublicGoodTrustedRoot(cacheDir string) func(context.Context) (root.TrustedMaterial, error) {
	var mu sync.Mutex
	var live *root.LiveTrustedRoot
	var lastErr error
	var lastTry time.Time
	return func(context.Context) (root.TrustedMaterial, error) {
		mu.Lock()
		defer mu.Unlock()
		if live != nil {
			return live, nil
		}
		if lastErr != nil && time.Since(lastTry) < 30*time.Second {
			return nil, lastErr
		}
		opts := tuf.DefaultOptions()
		if cacheDir != "" {
			opts = opts.WithCachePath(cacheDir)
		}
		lastTry = time.Now()
		live, lastErr = root.NewLiveTrustedRoot(opts)
		if lastErr != nil {
			live = nil
			return nil, lastErr
		}
		return live, nil
	}
}

// Sigstore bundle media types, as used for OCI referrers.
const bundleArtifactPrefix = "application/vnd.dev.sigstore.bundle"

// maxBundleSize bounds a single downloaded bundle.
const maxBundleSize = 4 << 20

// Registry finds bundles attached to the image as OCI referrers (with the
// referrers-tag fallback for registries without the Referrers API). This is
// where actions/attest-build-provenance stores them with push-to-registry.
type Registry struct {
	// Keychain supplies registry credentials. Default: docker config.
	Keychain authn.Keychain
	// MaxBundles bounds how many bundles are downloaded. Default 16.
	MaxBundles int
}

// Bundles implements BundleSource.
func (r Registry) Bundles(ctx context.Context, image string) ([][]byte, error) {
	d, err := name.NewDigest(image)
	if err != nil {
		return nil, err
	}
	kc := r.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(kc)}
	idx, err := remote.Referrers(d, opts...)
	if err != nil {
		return nil, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	limit := r.MaxBundles
	if limit == 0 {
		limit = 16
	}
	var out [][]byte
	for _, m := range im.Manifests {
		if !strings.HasPrefix(m.ArtifactType, bundleArtifactPrefix) {
			continue
		}
		if len(out) >= limit {
			break
		}
		img, err := remote.Image(d.Context().Digest(m.Digest.String()), opts...)
		if err != nil {
			return nil, err
		}
		layers, err := img.Layers()
		if err != nil {
			return nil, err
		}
		for _, l := range layers {
			b, err := readLayer(l.Compressed)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	}
	return out, nil
}

func readLayer(open func() (io.ReadCloser, error)) ([]byte, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxBundleSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBundleSize {
		return nil, errors.New("provenance bundle too large")
	}
	return b, nil
}

// Files reads bundles from local files, e.g. in a CI job that just built the
// image.
type Files []string

// Bundles implements BundleSource.
func (f Files) Bundles(context.Context, string) ([][]byte, error) {
	var out [][]byte
	for _, p := range f {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
