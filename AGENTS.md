# AGENTS.md — context for coding agents and contributors

## What this project is
shipgate is a deploy gate: code reaches production only if every commit was
signed with a physical FIDO2 key (touch + PIN), approved by a different
enrolled person with their own key, and verified at deploy time against gittuf
policy, independently of GitHub. Background: README.md, docs/design.md,
docs/threat-model.md. The full v0.1 plan with acceptance criteria is
docs/issues.md; issue numbers (#N) in code TODOs refer to it.

## Non-negotiable design rules
1. **Fail closed.** Any error, missing data or unimplemented step is a deny.
   Never return "allowed" from a code path you haven't verified.
2. **The gate never knows about audit mode.** internal/gate always returns the
   honest decision. Only callers (internal/webhook) decide whether to act on it.
3. **The forge is not a trust root.** Do not treat GitHub PR approvals, branch
   protection, the "Verified" badge or GitHub-signed merge commits as sufficient
   evidence. They can be used as extra signals, never as the deciding one.
4. **Keyless/OIDC signatures are not authorship.** They bind to the login that
   the threat model assumes is stolen. Authorship requires an enrolled sk key.
5. **Every deny has a reason** a human can act on (gate.Decision.Reason).
6. **Small dependency tree.** v0.1 core uses the standard library only. Adding
   a dependency (gittuf, sigstore-go, etc.) is fine when an issue needs it;
   say why in the PR. Avoid pulling in k8s.io/* for the webhook unless needed.
7. **Never weaken a default or a test to make something pass.** If a security
   test fails, the implementation is wrong or the issue needs discussion.

## Layout
- cmd/shipgate — stdlib CLI; subcommand table in commands.go
- internal/gate — the decision pipeline (provenance -> mirror -> policy)
- internal/provenance, internal/mirror, internal/gittufx — pipeline step
  interfaces, each with a NotImplemented default that denies
- internal/enroll — sk key generation + git config (implemented, #5)
- internal/webhook — AdmissionReview handler with audit/enforce modes
- internal/audit — structured JSON decision events
- internal/policy, internal/approve, internal/merge — package docs only, to implement
- policies/default — draft policy pack (schema not final, #9)
- deploy/helm/shipgate — webhook chart skeleton (#16)
- test/e2e — "stolen token" demo plan (#18)

## Working on it
- `make test` (go vet + go test), `make build` -> bin/shipgate, `make fmt`.
- go.mod targets Go 1.22. gittuf and sigstore-go may require a newer Go;
  bump go.mod when you add them.
- Module path is github.com/hsouf/shipgate.
- Use fakes (see internal/gate/gate_test.go) to test pipeline logic. Every new
  step needs at least one test proving a deny path.
- CI can't press a physical key. For tests, use a virtual FIDO authenticator
  or a test-only key type behind a build tag (#18); never ship that path.

## Suggested order of work
1. Spikes #3 (does gittuf enforce sk user-presence/verification flags?) and
   #4 (gittuf Go API vs CLI). Record findings in docs/design.md.
2. #13 provenance -> #14 mirror -> #15 verify, so `shipgate verify` works end to end.
3. #16/#17 webhook polish, then #8/#9 init, #10-#12 approve/merge, #6/#7 enroll.
4. #18 e2e demo, #19 docs.
