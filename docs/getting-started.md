# Getting started

> Pre-alpha. This guide will become the 15-minute quickstart in #19.

1. Get a FIDO2 security key (e.g. YubiKey 5 series) and OpenSSH 8.2+.
2. `shipgate enroll --comment you@example.com` (try `--dry-run` first).
3. `shipgate init` in the repo (not implemented yet, #8).
4. Install the webhook in audit-only mode (Helm chart in deploy/helm/shipgate, #16).
5. Watch would-deny events for a couple of weeks before passing `--enforce`.
