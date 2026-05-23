// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package hybrid combines classical (X25519, Ed25519) and post-quantum
// (ML-KEM-768, ML-DSA-65) primitives into the hybrid constructions used
// across Neverlur. It exports:
//
//   - CombineKEM: an HKDF-SHA512 KEM combiner that produces a 32-byte
//     session secret from an X25519 shared secret and an ML-KEM-768
//     shared secret, bound to a transcript and a context label.
//   - SignedMessage: the canonical byte string that hybrid signers and
//     verifiers agree on for a given artifact; binds the (Ed25519,
//     ML-DSA-65) identity pair.
//   - HybridIdentity / HybridIdentityPublic: the paired identity type
//     used by guardians, mixers, PKG, CDN, coordinator, and clients.
//   - IdentityFile: persistent on-disk format (.neverlur-id-v2) with
//     v1-to-v2 in-place upgrade.
//
// Design notes live in specs/001-pq-hybrid-crypto/research.md (R3, R4, R9)
// and specs/001-pq-hybrid-crypto/contracts/hybrid-combiner.md.
package hybrid
