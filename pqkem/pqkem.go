// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// Re-export size constants so callers do not need to import CIRCL directly.
const (
	PublicKeySize  = mlkem768.PublicKeySize  // 1184
	PrivateKeySize = mlkem768.PrivateKeySize // 2400
	CiphertextSize = mlkem768.CiphertextSize // 1088
	SharedKeySize  = mlkem768.SharedKeySize  // 32
	// EncapsulationSeedSize is the size of the deterministic-encapsulation
	// coin string consumed by EncapsulateDeterministic.
	EncapsulationSeedSize = mlkem768.EncapsulationSeedSize // 32
	// KeySeedSize is the size of the deterministic-keygen seed consumed
	// by NewKeyFromSeed.
	KeySeedSize = mlkem768.KeySeedSize // 64
)

// Re-export the CIRCL types so the rest of the codebase imports pqkem only.
type (
	PublicKey  = mlkem768.PublicKey
	PrivateKey = mlkem768.PrivateKey
)

// GenerateKey returns a fresh ML-KEM-768 keypair using crypto/rand.
func GenerateKey() (*PublicKey, *PrivateKey, error) {
	return mlkem768.GenerateKeyPair(rand.Reader)
}

// GenerateKeyFromReader returns a fresh ML-KEM-768 keypair drawing entropy
// from the supplied reader. Used by tests; production code should call
// GenerateKey.
func GenerateKeyFromReader(r io.Reader) (*PublicKey, *PrivateKey, error) {
	return mlkem768.GenerateKeyPair(r)
}

// NewKeyFromSeed returns the deterministic ML-KEM-768 keypair derived from
// the supplied seed. The seed must be exactly KeySeedSize bytes.
//
// This is used by the FIPS 203 known-answer tests and by any caller that
// needs reproducible key material; the regular friend-request flow uses
// GenerateKey instead.
func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey, error) {
	if len(seed) != KeySeedSize {
		return nil, nil, fmt.Errorf("pqkem: seed length %d, want %d", len(seed), KeySeedSize)
	}
	pk, sk := mlkem768.NewKeyFromSeed(seed)
	return pk, sk, nil
}

// Encapsulate produces a ciphertext + 32-byte shared secret addressed to pk.
// Returns ct (CiphertextSize bytes) and ss (SharedKeySize bytes).
func Encapsulate(pk *PublicKey) (ct, ss []byte, err error) {
	if pk == nil {
		return nil, nil, errors.New("pqkem: nil public key")
	}
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)
	seed := make([]byte, EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("pqkem: reading entropy: %w", err)
	}
	pk.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}

// EncapsulateDeterministic is the same as Encapsulate but uses the supplied
// EncapsulationSeedSize-byte coin string instead of fresh entropy. Used by
// the FIPS 203 known-answer tests; never call from production code.
func EncapsulateDeterministic(pk *PublicKey, seed []byte) (ct, ss []byte, err error) {
	if pk == nil {
		return nil, nil, errors.New("pqkem: nil public key")
	}
	if len(seed) != EncapsulationSeedSize {
		return nil, nil, fmt.Errorf("pqkem: seed length %d, want %d", len(seed), EncapsulationSeedSize)
	}
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)
	pk.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext under sk.
// On a malformed ciphertext the underlying primitive returns the
// implicit-rejection key (a 32-byte pseudorandom value deterministically
// derived from sk and the ciphertext), not an error — see FIPS 203
// §7.3, "Implicit Rejection". Callers that need to distinguish "valid
// ciphertext for this sk" from "anything else" must establish that
// property externally (e.g. by binding the ciphertext into a transcript
// the responder later commits to, as the hybrid combiner does).
func Decapsulate(sk *PrivateKey, ct []byte) (ss []byte, err error) {
	if sk == nil {
		return nil, errors.New("pqkem: nil private key")
	}
	if len(ct) != CiphertextSize {
		return nil, fmt.Errorf("pqkem: ciphertext length %d, want %d", len(ct), CiphertextSize)
	}
	ss = make([]byte, SharedKeySize)
	sk.DecapsulateTo(ss, ct)
	return ss, nil
}

// PackPublicKey returns the canonical PublicKeySize-byte serialization of pk.
func PackPublicKey(pk *PublicKey) []byte {
	buf := make([]byte, PublicKeySize)
	pk.Pack(buf)
	return buf
}

// UnpackPublicKey parses a canonical PublicKeySize-byte serialization.
func UnpackPublicKey(buf []byte) (*PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, fmt.Errorf("pqkem: public key length %d, want %d", len(buf), PublicKeySize)
	}
	pk := new(PublicKey)
	if err := pk.Unpack(buf); err != nil {
		return nil, fmt.Errorf("pqkem: unpack public key: %w", err)
	}
	return pk, nil
}

// PackPrivateKey returns the canonical PrivateKeySize-byte serialization of sk.
func PackPrivateKey(sk *PrivateKey) []byte {
	buf := make([]byte, PrivateKeySize)
	sk.Pack(buf)
	return buf
}

// UnpackPrivateKey parses a canonical PrivateKeySize-byte serialization.
func UnpackPrivateKey(buf []byte) (*PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, fmt.Errorf("pqkem: private key length %d, want %d", len(buf), PrivateKeySize)
	}
	sk := new(PrivateKey)
	if err := sk.Unpack(buf); err != nil {
		return nil, fmt.Errorf("pqkem: unpack private key: %w", err)
	}
	return sk, nil
}
