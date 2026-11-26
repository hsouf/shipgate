# E2E: the "stolen token" demo (#18)

Goal: show that a commit pushed with only a GitHub token never passes the gate.

Planned script:
1. Create a kind cluster and install the chart in audit mode.
2. Create a test repo with `shipgate init` and two enrolled test identities.
3. Happy path: author commits (signed), second identity approves, `shipgate merge`,
   build image with provenance, deploy -> allowed.
4. Attack path: push a commit using only a token (no sk signature), build, deploy
   -> would-deny event naming the unsigned commit.
5. Re-run step 4 with `enforce: true` -> admission denied.

CI can't press a physical key: use a virtual FIDO authenticator, or a test-only
key type behind a `//go:build e2e` tag. That path must never ship in releases.
