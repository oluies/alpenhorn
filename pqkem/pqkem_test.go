// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// TestRoundTrip is the wrapper-level happy path: a fresh keypair
// encapsulates and decapsulates back to the same shared secret.
func TestRoundTrip(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ct, ssA, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != CiphertextSize {
		t.Errorf("ct length = %d, want %d", len(ct), CiphertextSize)
	}
	if len(ssA) != SharedKeySize {
		t.Errorf("ss length = %d, want %d", len(ssA), SharedKeySize)
	}

	ssB, err := Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssA, ssB) {
		t.Fatalf("decapsulated shared secret mismatch")
	}
}

// TestPackUnpackPublicKey verifies the canonical serialization round-trips.
func TestPackUnpackPublicKey(t *testing.T) {
	pk, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	buf := PackPublicKey(pk)
	if len(buf) != PublicKeySize {
		t.Fatalf("packed length = %d, want %d", len(buf), PublicKeySize)
	}
	pk2, err := UnpackPublicKey(buf)
	if err != nil {
		t.Fatalf("UnpackPublicKey: %v", err)
	}
	buf2 := PackPublicKey(pk2)
	if !bytes.Equal(buf, buf2) {
		t.Fatalf("repack mismatch")
	}
}

// TestPackUnpackPrivateKey verifies the canonical serialization round-trips.
func TestPackUnpackPrivateKey(t *testing.T) {
	_, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	buf := PackPrivateKey(sk)
	if len(buf) != PrivateKeySize {
		t.Fatalf("packed length = %d, want %d", len(buf), PrivateKeySize)
	}
	sk2, err := UnpackPrivateKey(buf)
	if err != nil {
		t.Fatalf("UnpackPrivateKey: %v", err)
	}
	buf2 := PackPrivateKey(sk2)
	if !bytes.Equal(buf, buf2) {
		t.Fatalf("repack mismatch")
	}
}

// TestDeterministicEncapsulate verifies that the deterministic path is in
// fact deterministic, and that running the same coin against the same key
// twice produces identical (ct, ss).
func TestDeterministicEncapsulate(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed := make([]byte, EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		t.Fatalf("read seed: %v", err)
	}
	ct1, ss1, err := EncapsulateDeterministic(pk, seed)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic #1: %v", err)
	}
	ct2, ss2, err := EncapsulateDeterministic(pk, seed)
	if err != nil {
		t.Fatalf("EncapsulateDeterministic #2: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatalf("deterministic ct differs across calls with identical seed")
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatalf("deterministic ss differs across calls with identical seed")
	}
	ssBack, err := Decapsulate(sk, ct1)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ssBack) {
		t.Fatalf("decapsulated ss differs from deterministically encapsulated ss")
	}
}

// TestImplicitRejection confirms the FIPS 203 §7.3 contract: a malformed
// ciphertext does not error; it returns a 32-byte pseudorandom value
// derived from sk and ct. Two distinct malformed ciphertexts produce two
// distinct outputs; the same malformed ciphertext twice produces the
// same output.
func TestImplicitRejection(t *testing.T) {
	_, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bad1 := make([]byte, CiphertextSize)
	bad2 := make([]byte, CiphertextSize)
	if _, err := io.ReadFull(rand.Reader, bad1); err != nil {
		t.Fatalf("read bad1: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, bad2); err != nil {
		t.Fatalf("read bad2: %v", err)
	}
	ss1a, err := Decapsulate(sk, bad1)
	if err != nil {
		t.Fatalf("Decapsulate(bad1): %v", err)
	}
	ss1b, err := Decapsulate(sk, bad1)
	if err != nil {
		t.Fatalf("Decapsulate(bad1) repeat: %v", err)
	}
	ss2, err := Decapsulate(sk, bad2)
	if err != nil {
		t.Fatalf("Decapsulate(bad2): %v", err)
	}
	if !bytes.Equal(ss1a, ss1b) {
		t.Fatalf("implicit rejection is not deterministic for the same (sk, ct)")
	}
	if bytes.Equal(ss1a, ss2) {
		t.Fatalf("implicit rejection collided for two distinct malformed ciphertexts (1 in 2^256, look at this twice)")
	}
}

// TestRejectsBadInputs covers the wrapper's length checks.
func TestRejectsBadInputs(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, _, err := EncapsulateDeterministic(pk, make([]byte, 1)); err == nil {
		t.Errorf("expected error for short encap seed")
	}
	if _, err := Decapsulate(sk, make([]byte, 1)); err == nil {
		t.Errorf("expected error for short ciphertext")
	}
	if _, err := UnpackPublicKey(make([]byte, 1)); err == nil {
		t.Errorf("expected error for short packed public key")
	}
	if _, err := UnpackPrivateKey(make([]byte, 1)); err == nil {
		t.Errorf("expected error for short packed private key")
	}
	if _, _, err := NewKeyFromSeed(make([]byte, 1)); err == nil {
		t.Errorf("expected error for short keygen seed")
	}
}
