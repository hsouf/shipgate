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
- #3 gittuf + sk flags: _TBD_
- #4 Go API vs CLI: _TBD_
