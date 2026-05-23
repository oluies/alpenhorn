// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
)

// Re-export size constants so callers do not need to import CIRCL directly.
const (
	PublicKeySize  = mldsa65.PublicKeySize  // 1952
	PrivateKeySize = mldsa65.PrivateKeySize // 4032
	SignatureSize  = mldsa65.SignatureSize  // 3309
	SeedSize       = mldsa65.SeedSize       // 32
)

// Re-export the CIRCL types so the rest of the codebase imports pqsig only.
type (
	PublicKey  = mldsa65.PublicKey
	PrivateKey = mldsa65.PrivateKey
)

// bindingInfo is the HKDF info string that ties the ML-DSA-65 seed to the
// Ed25519 seed (research.md R4). Changing this string is a wire-incompatible
// change: every existing hybrid identity becomes unrecognizable.
const bindingInfo = "neverlur/v1 pq-id-binding"

// GenerateKey returns a fresh ML-DSA-65 keypair using crypto/rand.
func GenerateKey() (*PublicKey, *PrivateKey, error) {
	return mldsa65.GenerateKey(rand.Reader)
}

// GenerateKeyFromReader returns a fresh ML-DSA-65 keypair drawing entropy
// from the supplied reader. Used by tests.
func GenerateKeyFromReader(r io.Reader) (*PublicKey, *PrivateKey, error) {
	return mldsa65.GenerateKey(r)
}

// GenerateKeyFromSeed returns a deterministic ML-DSA-65 keypair from a
// SeedSize-byte seed. Used by both the FIPS 204 KAT and the hybrid
// identity binding (DeriveFromEd25519Seed).
func GenerateKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, fmt.Errorf("pqsig: seed length %d, want %d", len(seed), SeedSize)
	}
	var s [SeedSize]byte
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return pk, sk, nil
}

// DeriveFromEd25519Seed implements research.md R4: it returns the
// ML-DSA-65 keypair bound to the supplied Ed25519 seed.
//
// edSeed MUST be the 32-byte Ed25519 seed (the first 32 bytes of the
// 64-byte Ed25519 private key). The derivation is HKDF-SHA512 over the
// Ed25519 seed with a fixed info string; changing the info string is a
// wire-incompatible break.
//
// This function is the only place where ML-DSA-65 seeds are derived from
// classical material. Every hybrid identity in the deployment goes
// through here.
func DeriveFromEd25519Seed(edSeed []byte) (*PublicKey, *PrivateKey, error) {
	if len(edSeed) != 32 {
		return nil, nil, fmt.Errorf("pqsig: ed25519 seed length %d, want 32", len(edSeed))
	}
	r := hkdf.New(sha512.New, edSeed, nil, []byte(bindingInfo))
	mldsaSeed := make([]byte, SeedSize)
	if _, err := io.ReadFull(r, mldsaSeed); err != nil {
		return nil, nil, fmt.Errorf("pqsig: hkdf expand: %w", err)
	}
	return GenerateKeyFromSeed(mldsaSeed)
}

// Sign produces an ML-DSA-65 signature over msg under sk.
// The signature is randomized (FIPS 204 default).
func Sign(sk *PrivateKey, msg []byte) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("pqsig: nil private key")
	}
	sig := make([]byte, SignatureSize)
	// ctx = nil (no pre-hash domain separation; we apply our own outside).
	if err := mldsa65.SignTo(sk, msg, nil, true, sig); err != nil {
		return nil, fmt.Errorf("pqsig: SignTo: %w", err)
	}
	return sig, nil
}

// SignDeterministic produces a deterministic ML-DSA-65 signature over msg.
// Used by the FIPS 204 known-answer tests; production code should call Sign.
func SignDeterministic(sk *PrivateKey, msg []byte) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("pqsig: nil private key")
	}
	sig := make([]byte, SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		return nil, fmt.Errorf("pqsig: SignTo: %w", err)
	}
	return sig, nil
}

// Verify returns true iff sig is a valid ML-DSA-65 signature over msg under pk.
func Verify(pk *PublicKey, msg, sig []byte) bool {
	if pk == nil || len(sig) != SignatureSize {
		return false
	}
	return mldsa65.Verify(pk, msg, nil, sig)
}

// PackPublicKey returns the canonical PublicKeySize-byte serialization of pk.
func PackPublicKey(pk *PublicKey) []byte {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:]
}

// UnpackPublicKey parses a canonical PublicKeySize-byte serialization.
func UnpackPublicKey(buf []byte) (*PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, fmt.Errorf("pqsig: public key length %d, want %d", len(buf), PublicKeySize)
	}
	pk := new(PublicKey)
	var arr [PublicKeySize]byte
	copy(arr[:], buf)
	pk.Unpack(&arr)
	return pk, nil
}

// PackPrivateKey returns the canonical PrivateKeySize-byte serialization of sk.
func PackPrivateKey(sk *PrivateKey) []byte {
	var buf [PrivateKeySize]byte
	sk.Pack(&buf)
	return buf[:]
}

// UnpackPrivateKey parses a canonical PrivateKeySize-byte serialization.
func UnpackPrivateKey(buf []byte) (*PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, fmt.Errorf("pqsig: private key length %d, want %d", len(buf), PrivateKeySize)
	}
	sk := new(PrivateKey)
	var arr [PrivateKeySize]byte
	copy(arr[:], buf)
	sk.Unpack(&arr)
	return sk, nil
}
