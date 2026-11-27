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
