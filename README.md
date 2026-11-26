# shipgate

**A stolen GitHub account shouldn't be able to ship to production.**

shipgate is a deploy gate. It refuses to run code in production unless every
change was signed with a **physical security key**, approved by a **second
enrolled person**, and verified at deploy time against a policy that lives
**outside the code forge**.

> Status: **pre-alpha scaffold.** The CLI, gate pipeline and admission webhook
> skeleton exist and fail closed. Most verification steps are not implemented
> yet. See [docs/issues.md](docs/issues.md) for the v0.1 plan.

## Why

In November 2026 an attacker used a compromised employee GitHub account at
1Password to push malicious code into backend services, which then pulled
customer metadata. Vault contents stayed safe, but a valid GitHub session was
the only thing between the attacker and production. Most pipelines work the
same way.

Branch protection and required reviews are configured by GitHub accounts, so a
stolen admin account can relax them. Keyless signing binds to the same login
that was stolen. shipgate requires something a stolen token can't produce, and
checks it with something the stolen account can't reconfigure.

## How it works

| Attack step | shipgate control |
|---|---|
| Session or token stolen | Commits signed with a FIDO2 key, touch + PIN required (`shipgate enroll`) |
| Push from the stolen account | Second enrolled person approves with their own key (`shipgate approve`) |
| Build and deploy | Admission webhook verifies provenance and gittuf policy outside GitHub (`shipgate webhook-serve`) |
| Policy tampering | Trust root changes need M-of-N hardware signatures (gittuf root) |

shipgate builds on [gittuf](https://github.com/gittuf/gittuf) (policy and
reference state log), in-toto (attestations) and Sigstore/SLSA (build
provenance). It is an opinionated layer on top of them, not a replacement.

## What it won't stop

Read this before deploying it.

- Reading source code with a stolen token. Use short-lived tokens and keep secrets out of repos.
- A malicious workflow stealing CI secrets on an unprotected branch. Scope secrets to protected environments.
- Malware on a developer's machine waiting for a legitimate key touch. PIN-required keys reduce this; they don't eliminate it.
- Rubber-stamped reviews, insider collusion and poisoned dependencies.

See [docs/threat-model.md](docs/threat-model.md).

## Quick look

```sh
make build
./bin/shipgate                                   # list commands
./bin/shipgate enroll --dry-run --comment you@example.com
./bin/shipgate verify --image registry.example/app@sha256:...   # denies until #13-#15 land
```

## Roadmap

- **v0.1:** enroll, init (policy pack), approve, merge, verify, admission webhook in audit mode, "stolen token" e2e demo.
- **Later:** break-glass, merge bot with HSM key, Argo CD / Flux plugins, eBPF egress allowlist, GitHub audit-log detection.

## Contributing

Start with [docs/issues.md](docs/issues.md). Issues labelled `spike` come first
because their answers can change the design. `good-first-issue`: #9, #17.

## License

Apache-2.0
