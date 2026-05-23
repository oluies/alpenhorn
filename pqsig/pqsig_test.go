// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), SignatureSize)
	}
	if !Verify(pk, msg, sig) {
		t.Fatal("Verify rejected a valid signature")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("authentic")
	sig, _ := Sign(sk, msg)
	if Verify(pk, []byte("tampered"), sig) {
		t.Fatal("Verify accepted a signature over a tampered message")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("authentic")
	sig, _ := Sign(sk, msg)
	sig[0] ^= 0x01
	if Verify(pk, msg, sig) {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, sk, _ := GenerateKey()
	pkOther, _, _ := GenerateKey()
	msg := []byte("authentic")
	sig, _ := Sign(sk, msg)
	if Verify(pkOther, msg, sig) {
		t.Fatal("Verify accepted a signature under the wrong public key")
	}
}

func TestVerifyRejectsBadInputs(t *testing.T) {
	pk, sk, _ := GenerateKey()
	if Verify(nil, []byte("m"), make([]byte, SignatureSize)) {
		t.Errorf("Verify accepted nil public key")
	}
	if Verify(pk, []byte("m"), make([]byte, 1)) {
		t.Errorf("Verify accepted wrong-sized signature")
	}
	if _, err := Sign(nil, []byte("m")); err == nil {
		t.Errorf("Sign accepted nil private key")
	}
	_ = sk
}

func TestSignDeterministic(t *testing.T) {
	_, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("deterministic body")
	sig1, err := SignDeterministic(sk, msg)
	if err != nil {
		t.Fatalf("SignDeterministic #1: %v", err)
	}
	sig2, err := SignDeterministic(sk, msg)
	if err != nil {
		t.Fatalf("SignDeterministic #2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("SignDeterministic produced different signatures for identical (sk, msg)")
	}
}

func TestPackUnpack(t *testing.T) {
	pk, sk, _ := GenerateKey()
	pkBytes := PackPublicKey(pk)
	if len(pkBytes) != PublicKeySize {
		t.Fatalf("packed pub len = %d, want %d", len(pkBytes), PublicKeySize)
	}
	pk2, err := UnpackPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("UnpackPublicKey: %v", err)
	}
	if !bytes.Equal(pkBytes, PackPublicKey(pk2)) {
		t.Fatal("repack public mismatch")
	}
	skBytes := PackPrivateKey(sk)
	if len(skBytes) != PrivateKeySize {
		t.Fatalf("packed priv len = %d, want %d", len(skBytes), PrivateKeySize)
	}
	sk2, err := UnpackPrivateKey(skBytes)
	if err != nil {
		t.Fatalf("UnpackPrivateKey: %v", err)
	}
	if !bytes.Equal(skBytes, PackPrivateKey(sk2)) {
		t.Fatal("repack private mismatch")
	}
}

func TestGenerateKeyFromSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("read seed: %v", err)
	}
	pk1, sk1, err := GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed #1: %v", err)
	}
	pk2, sk2, err := GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed #2: %v", err)
	}
	if !bytes.Equal(PackPublicKey(pk1), PackPublicKey(pk2)) {
		t.Fatal("seed-derived public keys differ")
	}
	if !bytes.Equal(PackPrivateKey(sk1), PackPrivateKey(sk2)) {
		t.Fatal("seed-derived private keys differ")
	}
	if _, _, err := GenerateKeyFromSeed(make([]byte, 1)); err == nil {
		t.Error("GenerateKeyFromSeed accepted wrong-sized seed")
	}
}

func TestDeriveFromEd25519SeedBinding(t *testing.T) {
	// Use a real Ed25519 keypair; the derivation runs over the seed.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	edSeed := edPriv.Seed()
	pk1, sk1, err := DeriveFromEd25519Seed(edSeed)
	if err != nil {
		t.Fatalf("DeriveFromEd25519Seed #1: %v", err)
	}
	pk2, sk2, err := DeriveFromEd25519Seed(edSeed)
	if err != nil {
		t.Fatalf("DeriveFromEd25519Seed #2: %v", err)
	}
	if !bytes.Equal(PackPublicKey(pk1), PackPublicKey(pk2)) {
		t.Fatal("derivation is not deterministic in the Ed25519 seed")
	}
	if !bytes.Equal(PackPrivateKey(sk1), PackPrivateKey(sk2)) {
		t.Fatal("derivation is not deterministic in the Ed25519 seed (private)")
	}
	// Sanity: a different Ed25519 seed must produce a different ML-DSA-65 key.
	_, edPriv2, _ := ed25519.GenerateKey(rand.Reader)
	pk3, _, _ := DeriveFromEd25519Seed(edPriv2.Seed())
	if bytes.Equal(PackPublicKey(pk1), PackPublicKey(pk3)) {
		t.Fatal("two distinct Ed25519 seeds produced the same ML-DSA-65 public key")
	}
}
