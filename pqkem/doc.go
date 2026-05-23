// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package pqkem wraps CIRCL's ML-KEM-768 (FIPS 203) primitive with the
// minimal API that the Neverlur protocols use: generate, encapsulate,
// decapsulate, plus a deterministic-encapsulation entry point for known-
// answer testing.
//
// The wrapper deliberately exposes only the operations the rest of the
// codebase needs. Callers that want the full CIRCL surface should reach
// for github.com/cloudflare/circl/kem/mlkem/mlkem768 directly.
//
// Design notes and threat-model context live in
// specs/001-pq-hybrid-crypto/contracts/kat-mlkem768.md.
package pqkem
