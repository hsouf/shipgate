# Threat model

## Assumption
An engineer's GitHub account is compromised: the attacker holds a valid
session cookie and/or personal access token, possibly with org admin rights.
This is the starting point, not an edge case.

## Attacker goals in scope
1. Get attacker-authored code running in production.
2. Get code into production that no second person approved.
3. Change the policy or trust root so the above becomes possible.

## Controls
| Goal | Control | Where |
|---|---|---|
| 1 | Commits must carry a signature from an enrolled FIDO2 key with user-presence (and user-verification) flags | enroll, gittufx |
| 2 | Quorum approval from a different enrolled person, bound to the exact tree | approve, gittuf policy |
| 1, 2 | Deploy-time verification outside the forge: provenance -> source commit -> verified RSL entry | gate, webhook |
| 3 | Trust root changes need M-of-N root key signatures | gittuf root, init |

## Out of scope (documented limits)
- Reading source code with stolen credentials.
- Exfiltration of CI secrets by workflows on unprotected branches.
- Malware on the developer's machine that waits for a legitimate touch.
  Mitigation only: PIN-required keys, showing what is being signed.
- Reviewer negligence, insider collusion, compromised dependencies.
- Compromise of the deploy cluster itself.

## Emergency access
A break-glass path (post-v0.1) must be possible, loud (page + audit event) and
time-limited. Without it, teams remove the gate during the first outage.

## Open questions
- Does gittuf enforce sk user-presence / user-verification flags? (#3)
- How are merges recorded without a forge-signed merge commit? v0.1: local
  `shipgate merge`. v0.2: merge bot with an HSM-held key.
