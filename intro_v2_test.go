// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

// NOTE: this file lives in package `neverlur`, which transitively imports
// vuvuzela.io/crypto/bls -> bn256. The bn256 package ships hand-rolled
// x86_64-only assembly that does not build on arm64. As a result this
// test cannot be run locally on darwin/arm64; it runs in CI on
// linux/amd64. The non-network-protocol tests for the same code paths
// live in hybrid/, pqkem/, pqsig/, and keywheel/, all of which are
// bn256-free and run locally.

import (
	"bytes"
	"testing"

	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqkem"
	"github.com/oluies/neverlur/pqsig"
)

// makeV2 produces an introductionV2 with deterministic-but-arbitrary
// content (everything but signatures and ServerMultisig populated).
// Used by the wire-format and sign/verify tests below.
func makeV2(t *testing.T, id *hybrid.HybridIdentity) *introductionV2 {
	t.Helper()
	intro := new(introductionV2)
	for i := range intro.Username {
		intro.Username[i] = byte(i & 0xff)
	}
	for i := range intro.DHPublicKey {
		intro.DHPublicKey[i] = byte((i * 3) & 0xff)
	}
	pk, _, err := pqkem.GenerateKey()
	if err != nil {
		t.Fatalf("pqkem.GenerateKey: %v", err)
	}
	copy(intro.MLKEMPublicKey[:], pqkem.PackPublicKey(pk))
	intro.DialingRound = 12345
	copy(intro.LongTermKey[:], id.EdPub)
	copy(intro.LongTermKeyPQ[:], pqsig.PackPublicKey(id.PQPub))
	return intro
}

// TestIntroV2MarshalBinaryRoundtrip asserts wire-format encode/decode
// is the identity function.
func TestIntroV2MarshalBinaryRoundtrip(t *testing.T) {
	id, err := hybrid.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("GenerateHybridIdentity: %v", err)
	}
	intro := makeV2(t, id)
	if err := intro.Sign(id); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := intro.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(data) != SizeIntroV2 {
		t.Fatalf("marshaled length = %d, want %d", len(data), SizeIntroV2)
	}
	if data[0] != introductionV2Version {
		t.Fatalf("leading version byte = %#x, want %#x", data[0], introductionV2Version)
	}
	var got introductionV2
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	again, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary (repack): %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Fatal("repack produced different bytes")
	}
}

// TestIntroV2UnmarshalRejectsWrongVersion: a payload whose first byte
// is not 0x02 MUST be rejected. The v2 unmarshaler does NOT fall back
// to v1 on a version mismatch.
func TestIntroV2UnmarshalRejectsWrongVersion(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	_ = intro.Sign(id)
	data, _ := intro.MarshalBinary()
	data[0] = 0x01 // v1's leading byte (high byte of Username) is whatever; force the rejection path.
	var got introductionV2
	err := got.UnmarshalBinary(data)
	if err == nil {
		t.Fatal("UnmarshalBinary accepted wrong-version payload")
	}
}

// TestIntroV2UnmarshalRejectsWrongSize: payloads of wrong length MUST
// be rejected outright; the codec never attempts a partial read.
func TestIntroV2UnmarshalRejectsWrongSize(t *testing.T) {
	for _, n := range []int{0, 1, SizeIntroV2 - 1, SizeIntroV2 + 1, SizeIntroV2 * 2} {
		var got introductionV2
		err := got.UnmarshalBinary(make([]byte, n))
		if err == nil {
			t.Errorf("UnmarshalBinary accepted wrong-size payload (%d bytes)", n)
		}
	}
}

// TestIntroV2VerifyAcceptsValid: a freshly signed intro verifies under
// its own hybrid identity. PKG multisig check is skipped by passing an
// empty serverKeys slice (which makes the BLS check trivially succeed —
// the test asserts the two signature halves verify, not the PKG path).
func TestIntroV2VerifyAcceptsValid(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	if err := intro.Sign(id); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := intro.Verify(nil); err != nil {
		t.Fatalf("Verify (no PKG): %v", err)
	}
}

// TestIntroV2VerifyRejectsForgedClassicalSig: corrupting Signature MUST
// cause Verify to reject with a classical-failed error.
func TestIntroV2VerifyRejectsForgedClassicalSig(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	_ = intro.Sign(id)
	intro.Signature[0] ^= 0x01
	if err := intro.Verify(nil); err == nil {
		t.Fatal("Verify accepted forged classical signature")
	}
}

// TestIntroV2VerifyRejectsForgedPQSig: corrupting SignaturePQ MUST
// cause Verify to reject with a PQ-failed error.
func TestIntroV2VerifyRejectsForgedPQSig(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	_ = intro.Sign(id)
	intro.SignaturePQ[0] ^= 0x01
	if err := intro.Verify(nil); err == nil {
		t.Fatal("Verify accepted forged PQ signature")
	}
}

// TestIntroV2VerifyRejectsSubstitutedPQKey: an attacker who keeps a
// valid Ed25519 signature but substitutes LongTermKeyPQ for a
// different valid ML-DSA-65 public key MUST be rejected, because the
// SHA-512(LongTermKey || LongTermKeyPQ) hashed into the signed message
// no longer matches.
func TestIntroV2VerifyRejectsSubstitutedPQKey(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	_ = intro.Sign(id)
	other, _ := hybrid.GenerateHybridIdentity()
	copy(intro.LongTermKeyPQ[:], pqsig.PackPublicKey(other.PQPub))
	if err := intro.Verify(nil); err == nil {
		t.Fatal("Verify accepted intro with substituted PQ public key")
	}
}

// TestIntroV2SignedMessageBindsKeyHash: changing only the LongTermKey
// (with no corresponding re-sign) must invalidate the classical sig
// because the key hash inside signedMsg changes. This test belt-and-
// braces the binding guarantee.
func TestIntroV2SignedMessageBindsKeyHash(t *testing.T) {
	id, _ := hybrid.GenerateHybridIdentity()
	intro := makeV2(t, id)
	_ = intro.Sign(id)
	// Flip a bit of LongTermKey (without re-signing): both Ed25519 and
	// ML-DSA-65 verification must fail because the signed message now
	// hashes to a different value.
	intro.LongTermKey[0] ^= 0x01
	if err := intro.Verify(nil); err == nil {
		t.Fatal("Verify accepted intro with substituted classical pub key")
	}
}

// TestIntroV2SignRequiresPrivateKey: calling Sign with a verify-only
// identity (no Ed25519 priv) MUST error out.
func TestIntroV2SignRequiresPrivateKey(t *testing.T) {
	intro := new(introductionV2)
	err := intro.Sign(nil)
	if err == nil {
		t.Fatal("Sign accepted nil identity")
	}
	// Build an identity with no private material.
	src, _ := hybrid.GenerateHybridIdentity()
	verifyOnly := &hybrid.HybridIdentity{
		EdPub: src.EdPub,
		PQPub: src.PQPub,
	}
	err = intro.Sign(verifyOnly)
	if err == nil {
		t.Fatal("Sign accepted verify-only identity")
	}
}
