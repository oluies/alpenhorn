// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package pqsig wraps CIRCL's ML-DSA-65 (FIPS 204) primitive and supplies
// the Ed25519-seed-to-ML-DSA-65 binding derivation used to give every
// existing classical Neverlur identity a deterministic post-quantum
// counterpart.
//
// Callers wanting the full CIRCL surface should use
// github.com/cloudflare/circl/sign/mldsa/mldsa65 directly.
//
// Design notes and threat-model context live in
// specs/001-pq-hybrid-crypto/contracts/kat-mldsa65.md and research.md R4.
package pqsig
