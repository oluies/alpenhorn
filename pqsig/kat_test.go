// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// TestDeriveBindingStable is the deterministic KAT for the R4 hybrid
// identity binding. It loads testdata/binding-kat.json, re-runs
// DeriveFromEd25519Seed against the recorded Ed25519 seed, and asserts
// the SHA-256 of the resulting ML-DSA-65 public/private keys match the
// recorded values.
//
// If this test fails, one of these is true:
//
//	(a) pqsig.bindingInfo changed (wire-incompatible — every hybrid
//	    identity in every deployment becomes unrecognizable)
//	(b) CIRCL's ML-DSA-65 keygen output changed for a fixed seed
//	    (wire-incompatible — same problem)
//	(c) pqsig.DeriveFromEd25519Seed's HKDF parameters changed
//
// All three cases are release-blocking. There is no scenario in which
// this test should be silently updated.
func TestDeriveBindingStable(t *testing.T) {
	data, err := os.ReadFile("testdata/binding-kat.json")
	if err != nil {
		t.Fatalf("read binding KAT: %v", err)
	}
	var kat struct {
		EdSeedHex       string `json:"ed25519_seed_hex"`
		ExpectedPubHash string `json:"expected_pq_pub_sha256"`
		ExpectedSkHash  string `json:"expected_pq_sk_sha256"`
		ExpectedPubSize string `json:"expected_pq_pub_size"`
		ExpectedSkSize  string `json:"expected_pq_sk_size"`
	}
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatalf("parse binding KAT: %v", err)
	}
	edSeed, err := hex.DecodeString(kat.EdSeedHex)
	if err != nil {
		t.Fatalf("decode ed seed: %v", err)
	}
	pk, sk, err := DeriveFromEd25519Seed(edSeed)
	if err != nil {
		t.Fatalf("DeriveFromEd25519Seed: %v", err)
	}
	pkBytes := PackPublicKey(pk)
	skBytes := PackPrivateKey(sk)

	if got, err := strconv.Atoi(kat.ExpectedPubSize); err == nil && len(pkBytes) != got {
		t.Errorf("pub key length = %d, want %d", len(pkBytes), got)
	}
	if got, err := strconv.Atoi(kat.ExpectedSkSize); err == nil && len(skBytes) != got {
		t.Errorf("priv key length = %d, want %d", len(skBytes), got)
	}

	pkHash := sha256.Sum256(pkBytes)
	skHash := sha256.Sum256(skBytes)
	if got := hex.EncodeToString(pkHash[:]); got != kat.ExpectedPubHash {
		t.Errorf("derived pub SHA-256 = %s\n           want %s\nBinding broken: see binding-kat.json comment", got, kat.ExpectedPubHash)
	}
	if got := hex.EncodeToString(skHash[:]); got != kat.ExpectedSkHash {
		t.Errorf("derived priv SHA-256 = %s\n           want %s\nBinding broken: see binding-kat.json comment", got, kat.ExpectedSkHash)
	}
}

// TestACVPKAT is the FIPS 204 known-answer test entry point. It loads
// testdata/fips204-vectors.json. While the file is the shipped placeholder
// (empty vectors slice with _status == "placeholder"), the test skips with
// a clear message; a green run does NOT mean FIPS 204 KAT has been
// validated. The constitution Quality Gate is satisfied only once
// authoritative vectors are committed and this test runs against them.
//
// Note: CIRCL ships gzipped NIST ACVP vectors for ML-DSA-65 under its own
// testdata directory and runs them in its TestACVP. That coverage is
// transitive: as long as we depend on a CIRCL version whose own TestACVP
// passed, the underlying primitive is FIPS 204-conformant. This test
// adds project-side, auditable KAT coverage on top of that.
func TestACVPKAT(t *testing.T) {
	data, err := os.ReadFile("testdata/fips204-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v struct {
		Status  string            `json:"_status"`
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Status == "placeholder" || len(v.Vectors) == 0 {
		t.Skipf("testdata/fips204-vectors.json is a placeholder; FIPS 204 KAT not validated. " +
			"Replace with authoritative NIST ACVP-Server vectors before relying on this test.")
	}
	// When real vectors land, expand this loop to cover keyGen, sigGen,
	// and sigVer per the structure documented in contracts/kat-mldsa65.md.
	t.Fatalf("FIPS 204 KAT vectors present but no case handler implemented yet")
}
