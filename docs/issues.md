# v0.1 issue list

Source of truth for the v0.1 plan. Code TODOs reference these numbers.
Run `scripts/create-issues.sh` once (needs the `gh` CLI, authenticated) to create
labels, milestones and issues in the GitHub repo. GitHub may assign different
issue numbers if the repo already has issues; update TODOs if so.

## M0: Foundations and spikes

### #1 Scaffold repo and release pipeline
Labels: `foundations`

Go module and CLI exist (scaffold). Add goreleaser builds for linux and darwin on amd64 and arm64, sign releases and publish SLSA provenance. Pin all GitHub Actions to commit SHAs.

**Done when:** `shipgate version` installs from a signed release with provenance.

### #2 Write the threat model
Labels: `docs`

Expand docs/threat-model.md from the article: in-scope goals, controls, documented limits.

**Done when:** Every v0.1 feature traces to a threat in the doc.

### #3 Spike: does gittuf enforce touch and PIN flags on security-key signatures?
Labels: `spike`

Sign with a key created with `-O no-touch-required` (signatures lack the user-presence flag) and check whether `gittuf verify-ref` rejects it. Repeat for user verification.

**Done when:** Answer recorded in docs/design.md; if no, upstream issue filed and a shipgate-side check scoped in internal/gittufx.

### #4 Spike: gittuf Go API vs shelling out
Labels: `spike`

Evaluate github.com/gittuf/gittuf/experimental/gittuf for policy init, attestations and verification.

**Done when:** Decision recorded in docs/design.md; internal/gittufx follows it.

## M1: Enrollment

### #5 shipgate enroll: key generation and git config
Labels: `enrollment`

Implemented in scaffold: ed25519-sk with verify-required, write-attestation, gpg.format ssh, user.signingkey, commit/tag signing. Harden: detect OpenSSH version, existing config, Windows.

**Done when:** A fresh machine produces commits that pass `git verify-commit` with the enrolled key.

### #6 FIDO attestation verification
Labels: `enrollment`

Verify the attestation written at keygen against an allowlist of authenticator models (AAGUIDs).

**Done when:** Software-only keys are rejected at enrollment.

### #7 Register enrolled person in policy
Labels: `enrollment`

Enrollment produces a staged gittuf policy change adding the person; it only applies once the root threshold signs it.

**Done when:** A new key can't sign valid commits until 2 of 3 root holders approve.

## M2: Policy pack

### #8 shipgate init: bootstrap the default policy
Labels: `policy`

Create a 2-of-3 gittuf root and a targets policy: main requires two distinct people; .github/workflows/ and deploy configs require a security approver; policy changes require the root threshold.

**Done when:** `shipgate init` followed by `gittuf verify-ref main` passes on a test repo.

### #9 Policy pack as overridable YAML
Labels: `policy`, `good-first-issue`

Load policies/default/*.yaml with a local override file for team names, paths and thresholds.

**Done when:** A team can change protected paths without editing Go code.

## M3: Approve and merge

### #10 shipgate approve
Labels: `approvals`

Create a key-touched approval attestation bound to the exact tree. Reject approvals by the commit author. Forge-sourced approvals are never sufficient alone.

**Done when:** Verification passes only with a valid approval from a second enrolled person.

### #11 Invalidate stale approvals
Labels: `approvals`

An approval is void if the tree changes after signing (new commit, force-push).

**Done when:** Pushing after approval makes verification fail.

### #12 shipgate merge
Labels: `approvals`

Check approvals, merge locally, sign the merge, record the RSL entry, push the branch with refs/gittuf/*. Handle a remote that moved mid-merge.

**Done when:** Author -> approve -> merge verifies end to end.

## M4: Deploy gate

### #13 Provenance verification
Labels: `gate`

Given an image digest, fetch and verify SLSA provenance with sigstore-go against an allowlist of trusted builder identities; extract source repo and commit. Implement provenance.Verifier.

**Done when:** Images from untrusted builders or without provenance are denied.

### #14 Repo mirror
Labels: `gate`

Local mirror including refs/gittuf/*, periodic sync, staleness bound; configurable fail-open/fail-closed when stale (default closed). Implement mirror.Mirror.

**Done when:** The gate keeps working with GitHub unreachable.

### #15 shipgate verify end to end
Labels: `gate`

Implement gittufx.PolicyVerifier and wire provenance -> mirror -> verify-ref -> commit matches a verified RSL entry.

**Done when:** Correct allow/deny for a fixture set of good and bad images.

### #16 shipgate webhook-serve and Helm chart
Labels: `gate`, `deploy`

Skeleton exists (audit/enforce, AdmissionReview parsing). Add cert management, timeouts and latency budget, per-digest decision cache, finish the chart.

**Done when:** Installs with Helm on kind and logs would-deny events without blocking.

### #17 Structured audit events and notifications
Labels: `gate`, `good-first-issue`

JSON events exist. Add policy version to events and optional Slack / generic webhook notification on would-deny.

**Done when:** Every decision is traceable to image, commit, policy version and reason.

## M5: Demo and docs

### #18 End-to-end stolen token demo
Labels: `e2e`

On kind: push a commit with only a GitHub token, build and deploy it, show the gate flagging it. Use a virtual FIDO authenticator or test-only key type behind a build tag for CI.

**Done when:** Runs in CI and as a script in the README.

### #19 README and getting-started guide
Labels: `docs`

15-minute quickstart; keep 'what it won't stop' near the top.

**Done when:** Someone outside the project gets audit mode running from the docs alone.

## Explicitly out of v0.1

Break-glass, merge bot with HSM key, Argo CD / Flux plugins, eBPF egress allowlist, GitHub audit-log detection.
