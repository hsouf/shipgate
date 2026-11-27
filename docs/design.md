# Design notes

## Decision pipeline (internal/gate)

```
image digest
  -> verify SLSA provenance, trusted builder only      (#13)
  -> extract source repo + commit
  -> fetch repo incl. refs/gittuf/* from a mirror      (#14)
  -> gittuf verify-ref on the protected branch          (#15)
  -> confirm commit matches a verified RSL entry        (#15)
  -> allow, or deny with a reason
```

Each step is an interface with a NotImplemented default that denies, so the
binary is always safe to run even while incomplete.

## Why build on gittuf
gittuf already provides a signed reference state log (refs/gittuf/reference-state-log),
TUF-style policy with thresholds (refs/gittuf/policy), a root of trust whose
changes need a threshold of root keys, approval attestations, and verify-ref.
shipgate adds hardware-key enrollment, an opinionated policy pack, a local
merge flow, and a deploy-time gate.

## Merges
A merge made with the forge's button is signed by the forge, whose key is not
in the gittuf delegation graph. v0.1 merges locally (`shipgate merge`). v0.2
may add a merge bot with one HSM-backed key that records RSL entries only after
verifying hardware-signed author + approver on the exact tree.

## Spike results
- #3 gittuf + sk flags: not yet tested with hardware. From reading gittuf
  v0.18.0, SSH signatures are verified with hiddeco/sshsig on top of
  golang.org/x/crypto/ssh, which checks the signature but not the
  user-presence or user-verification flags. Until the spike proves otherwise,
  shipgate checks the flags itself (internal/sshsig, change.HardwareVerifier)
  for commits and approvals in `approve` and `merge`. The deploy gate (#15)
  needs the same check.
- #4 Go API vs CLI: CLI. gittuf v0.18 requires Go 1.27 and pulls in a large
  dependency tree; shipgate shells out to the `gittuf` binary through
  internal/gittufx (`gittufx.Tool`), so the choice can change in one place.

## Approve and merge (#10-#12)
`shipgate approve <branch>`:
1. `gittuf sync`, fetch both branches; local branches must equal the remote.
2. Every commit in target..branch must be signed by a security key with touch
   and PIN flags (verified with `ssh-keygen -Y check-novalidate`).
3. The approver's key must not have signed any of those commits.
4. Show base, merge tree (`git merge-tree --write-tree`), commits and diffstat.
5. `gittuf attest authorize`, then check gittuf recorded an approval by this
   key for exactly that (base, tree). gittuf computes the tree from its RSL,
   so a mismatch means the RSL and the branch disagree; local refs are rolled
   back and nothing is pushed.
6. `gittuf attest apply --local-only`, then an atomic, non-forced push of
   refs/gittuf/attestations and the RSL.

`shipgate merge <branch>`:
1. Same sync and commit-signature checks.
2. Read the approval envelope at
   `reference-authorizations/<target>/<base>-<tree>` in refs/gittuf/attestations,
   check the in-toto statement matches that path, verify each DSSE signature
   (sk key, touch + PIN) and require one from a key that signed no commit.
3. `gittuf verify-mergeable` for policy: enrolled principals, thresholds.
4. `git commit-tree -S` with exactly the approved tree; verify its signature
   and tree; move the branch; `gittuf rsl record --local-only`;
   `gittuf verify-ref`.
5. Atomic push of the branch and the RSL. On any failure after the branch
   moved, the branch and the RSL are rolled back.

Key comparison is a pre-check. "Different person" is decided by gittuf policy,
which maps keys to principals, via verify-mergeable and verify-ref.

## Mirror (#14)
`internal/mirror` keeps a bare mirror per allowlisted repo. The forge's
branches go to `refs/remotes/forge/heads/*` and are never trusted. gittuf refs
are fetched into a staging namespace and only promoted to `refs/gittuf/*` if
the RSL, attestations and policy refs moved forward; a rewrite or deletion is
refused as possible tampering. Fetches happen at most every refresh interval
(the webhook also refreshes in the background). If fetching fails, the last
good mirror is used until `--mirror-max-staleness`, then the gate denies.
`--allow-stale-mirror` opts out; a stale mirror can miss a key revocation.

## Deploy-time verification (#15)
`internal/rslcheck` implements `gittufx.PolicyVerifier`. A commit is
deployable from a protected ref when:
1. it is the target of an RSL entry for the ref that no annotation skips;
2. `gittuf verify-ref` passes. Before running it, the ref in the mirror is set
   to its latest RSL entry, so a direct push to the forge can't break
   verification of legitimate commits; it just isn't deployable;
3. shipgate's own checks, the same rules as `shipgate merge`: the RSL entry,
   the merge commit and every commit it brings in are signed by a security
   key with touch + PIN, and an approval for the exact (previous entry, tree)
   is signed with touch + PIN by a key that signed none of those commits.

The first RSL entry for a ref has no predecessor and therefore no approval;
it is not deployable. Results are cached by (commit, RSL tip, attestations
tip); failures are cached for a minute at most.

`shipgate verify --repo ID --commit SHA` runs steps 1-3 without provenance,
for CD pipelines that already know the commit. Admission control needs #13
to tie an image to its commit.

## Provenance (#13)
`internal/provenance` maps an image digest to (repo, commit) using Sigstore
build provenance, so any CI that gets Fulcio certificates works (GitHub
Actions, GitLab, Buildkite...).
1. Find Sigstore bundles attached to the image as OCI referrers (with the
   referrers-tag fallback), which is where `actions/attest-build-provenance`
   with `push-to-registry: true` puts them. `verify --provenance-bundle` reads
   a file instead.
2. sigstore-go verifies the bundle: Fulcio chain, Rekor inclusion and SCTs
   (public-good instance; `--sigstore-no-tlog` for timestamp-authority-only
   instances like GitHub's private-repo one), and that the in-toto subject is
   the image digest.
3. The repo and commit come from the certificate (SourceRepositoryURI,
   SourceRepositoryDigest), which the CI's OIDC token sets. The SLSA
   predicate is generated by the build, so it is only cross-checked: naming a
   different commit for the source repo is a deny.
4. Builder policy: trusted OIDC issuer (default GitHub Actions), hosted runner
   (self-hosted is opt-in), trigger in push/workflow_dispatch/release/schedule
   (pull_request_target is excluded: it runs trusted workflow code on
   untrusted PR input), and the signing workflow must be in the source repo
   at the built commit, or match `--builder-signer` (reusable workflows).

The trusted root comes from Sigstore's TUF repository and is refreshed; a
failed fetch denies and is retried. `--sigstore-trusted-root` pins a file for
offline clusters or other instances.

Keyless signatures are not authorship. Provenance only says which commit was
built; the gittuf checks decide whether that commit may ship.

Known limit: a build workflow at an approved commit can still choose to build
other code (e.g. check out a ref from an input). Keep release workflows
building the commit they run on.
