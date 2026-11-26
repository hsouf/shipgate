#!/usr/bin/env bash
# Creates labels, milestones and v0.1 issues in the current GitHub repo.
# Requires: gh CLI authenticated (gh auth login), run from inside the repo.
# Run once; re-running creates duplicate issues.
set -euo pipefail

for l in spike foundations docs enrollment policy approvals gate deploy e2e good-first-issue; do
  gh label create "$l" --force >/dev/null
done

gh api repos/{owner}/{repo}/milestones -f title='M0: Foundations and spikes' >/dev/null 2>&1 || true
gh api repos/{owner}/{repo}/milestones -f title='M1: Enrollment' >/dev/null 2>&1 || true
gh api repos/{owner}/{repo}/milestones -f title='M2: Policy pack' >/dev/null 2>&1 || true
gh api repos/{owner}/{repo}/milestones -f title='M3: Approve and merge' >/dev/null 2>&1 || true
gh api repos/{owner}/{repo}/milestones -f title='M4: Deploy gate' >/dev/null 2>&1 || true
gh api repos/{owner}/{repo}/milestones -f title='M5: Demo and docs' >/dev/null 2>&1 || true

gh issue create --title 'Scaffold repo and release pipeline' --label 'foundations' --milestone 'M0: Foundations and spikes' --body 'Go module and CLI exist (scaffold). Add goreleaser builds for linux and darwin on amd64 and arm64, sign releases and publish SLSA provenance. Pin all GitHub Actions to commit SHAs.

**Done when:** `shipgate version` installs from a signed release with provenance.

Spec: docs/issues.md (#1)'
gh issue create --title 'Write the threat model' --label 'docs' --milestone 'M0: Foundations and spikes' --body 'Expand docs/threat-model.md from the article: in-scope goals, controls, documented limits.

**Done when:** Every v0.1 feature traces to a threat in the doc.

Spec: docs/issues.md (#2)'
gh issue create --title 'Spike: does gittuf enforce touch and PIN flags on security-key signatures?' --label 'spike' --milestone 'M0: Foundations and spikes' --body 'Sign with a key created with `-O no-touch-required` (signatures lack the user-presence flag) and check whether `gittuf verify-ref` rejects it. Repeat for user verification.

**Done when:** Answer recorded in docs/design.md; if no, upstream issue filed and a shipgate-side check scoped in internal/gittufx.

Spec: docs/issues.md (#3)'
gh issue create --title 'Spike: gittuf Go API vs shelling out' --label 'spike' --milestone 'M0: Foundations and spikes' --body 'Evaluate github.com/gittuf/gittuf/experimental/gittuf for policy init, attestations and verification.

**Done when:** Decision recorded in docs/design.md; internal/gittufx follows it.

Spec: docs/issues.md (#4)'
gh issue create --title 'shipgate enroll: key generation and git config' --label 'enrollment' --milestone 'M1: Enrollment' --body 'Implemented in scaffold: ed25519-sk with verify-required, write-attestation, gpg.format ssh, user.signingkey, commit/tag signing. Harden: detect OpenSSH version, existing config, Windows.

**Done when:** A fresh machine produces commits that pass `git verify-commit` with the enrolled key.

Spec: docs/issues.md (#5)'
gh issue create --title 'FIDO attestation verification' --label 'enrollment' --milestone 'M1: Enrollment' --body 'Verify the attestation written at keygen against an allowlist of authenticator models (AAGUIDs).

**Done when:** Software-only keys are rejected at enrollment.

Spec: docs/issues.md (#6)'
gh issue create --title 'Register enrolled person in policy' --label 'enrollment' --milestone 'M1: Enrollment' --body 'Enrollment produces a staged gittuf policy change adding the person; it only applies once the root threshold signs it.

**Done when:** A new key can'"'"'t sign valid commits until 2 of 3 root holders approve.

Spec: docs/issues.md (#7)'
gh issue create --title 'shipgate init: bootstrap the default policy' --label 'policy' --milestone 'M2: Policy pack' --body 'Create a 2-of-3 gittuf root and a targets policy: main requires two distinct people; .github/workflows/ and deploy configs require a security approver; policy changes require the root threshold.

**Done when:** `shipgate init` followed by `gittuf verify-ref main` passes on a test repo.

Spec: docs/issues.md (#8)'
gh issue create --title 'Policy pack as overridable YAML' --label 'policy,good-first-issue' --milestone 'M2: Policy pack' --body 'Load policies/default/*.yaml with a local override file for team names, paths and thresholds.

**Done when:** A team can change protected paths without editing Go code.

Spec: docs/issues.md (#9)'
gh issue create --title 'shipgate approve' --label 'approvals' --milestone 'M3: Approve and merge' --body 'Create a key-touched approval attestation bound to the exact tree. Reject approvals by the commit author. Forge-sourced approvals are never sufficient alone.

**Done when:** Verification passes only with a valid approval from a second enrolled person.

Spec: docs/issues.md (#10)'
gh issue create --title 'Invalidate stale approvals' --label 'approvals' --milestone 'M3: Approve and merge' --body 'An approval is void if the tree changes after signing (new commit, force-push).

**Done when:** Pushing after approval makes verification fail.

Spec: docs/issues.md (#11)'
gh issue create --title 'shipgate merge' --label 'approvals' --milestone 'M3: Approve and merge' --body 'Check approvals, merge locally, sign the merge, record the RSL entry, push the branch with refs/gittuf/*. Handle a remote that moved mid-merge.

**Done when:** Author -> approve -> merge verifies end to end.

Spec: docs/issues.md (#12)'
gh issue create --title 'Provenance verification' --label 'gate' --milestone 'M4: Deploy gate' --body 'Given an image digest, fetch and verify SLSA provenance with sigstore-go against an allowlist of trusted builder identities; extract source repo and commit. Implement provenance.Verifier.

**Done when:** Images from untrusted builders or without provenance are denied.

Spec: docs/issues.md (#13)'
gh issue create --title 'Repo mirror' --label 'gate' --milestone 'M4: Deploy gate' --body 'Local mirror including refs/gittuf/*, periodic sync, staleness bound; configurable fail-open/fail-closed when stale (default closed). Implement mirror.Mirror.

**Done when:** The gate keeps working with GitHub unreachable.

Spec: docs/issues.md (#14)'
gh issue create --title 'shipgate verify end to end' --label 'gate' --milestone 'M4: Deploy gate' --body 'Implement gittufx.PolicyVerifier and wire provenance -> mirror -> verify-ref -> commit matches a verified RSL entry.

**Done when:** Correct allow/deny for a fixture set of good and bad images.

Spec: docs/issues.md (#15)'
gh issue create --title 'shipgate webhook-serve and Helm chart' --label 'gate,deploy' --milestone 'M4: Deploy gate' --body 'Skeleton exists (audit/enforce, AdmissionReview parsing). Add cert management, timeouts and latency budget, per-digest decision cache, finish the chart.

**Done when:** Installs with Helm on kind and logs would-deny events without blocking.

Spec: docs/issues.md (#16)'
gh issue create --title 'Structured audit events and notifications' --label 'gate,good-first-issue' --milestone 'M4: Deploy gate' --body 'JSON events exist. Add policy version to events and optional Slack / generic webhook notification on would-deny.

**Done when:** Every decision is traceable to image, commit, policy version and reason.

Spec: docs/issues.md (#17)'
gh issue create --title 'End-to-end stolen token demo' --label 'e2e' --milestone 'M5: Demo and docs' --body 'On kind: push a commit with only a GitHub token, build and deploy it, show the gate flagging it. Use a virtual FIDO authenticator or test-only key type behind a build tag for CI.

**Done when:** Runs in CI and as a script in the README.

Spec: docs/issues.md (#18)'
gh issue create --title 'README and getting-started guide' --label 'docs' --milestone 'M5: Demo and docs' --body '15-minute quickstart; keep '"'"'what it won'"'"'t stop'"'"' near the top.

**Done when:** Someone outside the project gets audit mode running from the docs alone.

Spec: docs/issues.md (#19)'
echo "Done."
