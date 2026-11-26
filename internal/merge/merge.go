// Package merge performs a local merge into a protected branch, signs it with
// the enrolled key, records the gittuf RSL entry and pushes the branch along
// with refs/gittuf/*.
//
// Why local: a merge made by the forge's button is signed by the forge, not
// by a key in the gittuf delegation graph, so it cannot satisfy policy. A
// merge bot with an HSM-held key is planned for v0.2.
//
// TODO(#12): implement, including handling a remote that moved mid-merge.
package merge
