// Package approve creates hardware-signed approval attestations bound to the
// exact tree being approved.
//
// Rules:
//   - the approver must be an enrolled person different from the author;
//   - the approval binds to the from/to tree, so any later change voids it (#11);
//   - approvals sourced from the forge (e.g. GitHub PR reviews) are NOT
//     sufficient on their own, because they inherit the forge's trust.
//
// TODO(#10): implement on gittuf's reference authorization attestations.
package approve
