// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Domain-separation labels for the KEM combiner. Defined in
// contracts/hybrid-combiner.md. Adding a new context is a wire-incompatible
// change: callers that derive material under the new context will not
// interoperate with peers that still use the old context.
const (
	ContextFriendRequest = "friend-request"
	ContextKeywheelSeed  = "keywheel-seed"
	ContextEdTLSSession  = "edtls-session"
)

// SessionSecretSize is the size of the byte slice returned by CombineKEM.
// Matches keywheel's [32]byte secret type so the output is a drop-in.
const SessionSecretSize = 32

// X25519SharedSize is the required length of the X25519 component fed into
// CombineKEM. Curve25519 ECDH outputs are 32 bytes.
const X25519SharedSize = 32

// MLKEMSharedSize is the required length of the ML-KEM-768 component fed
// into CombineKEM. ML-KEM-768 shared secrets are 32 bytes (FIPS 203).
const MLKEMSharedSize = 32

// SigMessagePrefix is the domain separator embedded by SignedMessage.
// Defined in contracts/hybrid-combiner.md.
const SigMessagePrefix = "neverlur-hybrid-sig-v1"

// hkdfInfoPrefix is the prefix of the HKDF "info" parameter for CombineKEM.
// The full info is hkdfInfoPrefix || context.
const hkdfInfoPrefix = "neverlur/v1 hybrid kdf "

var (
	// ErrInvalidShareLength is returned by CombineKEM if either shared-secret
	// input is not exactly 32 bytes.
	ErrInvalidShareLength = errors.New("hybrid: KEM share must be 32 bytes")

	// ErrEmptyTranscript is returned by CombineKEM if transcript is nil or
	// zero-length.
	ErrEmptyTranscript = errors.New("hybrid: transcript must not be empty")

	// ErrEmptyContext is returned by CombineKEM if context is the empty
	// string.
	ErrEmptyContext = errors.New("hybrid: context label must not be empty")
)

// CombineKEMConcat is the variable-length-PQ-input variant of CombineKEM,
// added to support the option-F static-ephemeral hybrid design in
// docs/wire-introduction-v2.md where each side has TWO ML-KEM shared
// secrets per friendship (ssOutgoing and ssIncoming). The caller
// concatenates the two 32-byte secrets in canonical order and hands the
// 64-byte blob to this function as ssMLKEM.
//
// The function accepts any non-empty ssMLKEM blob; it is the caller's
// responsibility to enforce the structural invariant (currently
// 2 × 32 = 64 bytes). Future hybrids that mix in more or fewer PQ
// secrets reuse this entry point with a different blob length.
//
// All other arguments and security properties match CombineKEM.
func CombineKEMConcat(context string, transcript, ssX25519, ssMLKEM []byte) (*[SessionSecretSize]byte, error) {
	if context == "" {
		return nil, ErrEmptyContext
	}
	if len(ssX25519) != X25519SharedSize {
		return nil, ErrInvalidShareLength
	}
	if len(ssMLKEM) == 0 {
		return nil, ErrInvalidShareLength
	}
	if len(transcript) == 0 {
		return nil, ErrEmptyTranscript
	}

	saltSum := sha512.Sum512(transcript)
	ikm := make([]byte, 0, len(ssX25519)+len(ssMLKEM))
	ikm = append(ikm, ssX25519...)
	ikm = append(ikm, ssMLKEM...)

	info := []byte(hkdfInfoPrefix + context)
	r := hkdf.New(sha512.New, ikm, saltSum[:], info)

	out := new([SessionSecretSize]byte)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return nil, err
	}
	return out, nil
}

// CombineKEM derives a SessionSecretSize-byte session secret from a
// classical X25519 shared secret and an ML-KEM-768 shared secret, binding
// both to the supplied transcript and to a domain-separation context label.
//
// See contracts/hybrid-combiner.md and research.md R3 for the full design.
//
// Security property: an adversary who learns either ssX25519 or ssMLKEM
// but not both cannot derive the returned session secret. This is the
// half-compromise resistance the SC-003/SC-004 tests verify.
//
// Callers MUST NOT reuse the same (context, transcript, ssX25519, ssMLKEM)
// tuple across distinct handshakes. The transcript is the binding to the
// specific handshake instance; reusing it across handshakes recycles the
// session secret, defeating forward secrecy.
func CombineKEM(context string, transcript, ssX25519, ssMLKEM []byte) (*[SessionSecretSize]byte, error) {
	if context == "" {
		return nil, ErrEmptyContext
	}
	if len(ssX25519) != X25519SharedSize {
		return nil, ErrInvalidShareLength
	}
	if len(ssMLKEM) != MLKEMSharedSize {
		return nil, ErrInvalidShareLength
	}
	if len(transcript) == 0 {
		return nil, ErrEmptyTranscript
	}

	// Salt = SHA-512 of the transcript. Mixing the transcript through a
	// salt rather than directly into ikm gives HKDF's salt parameter a
	// non-trivial role and lets HKDF act as a randomness extractor.
	saltSum := sha512.Sum512(transcript)

	// ikm = ssX25519 || ssMLKEM. Both are uniform 32-byte secrets; their
	// concatenation is the input keying material the combiner extracts from.
	ikm := make([]byte, 0, X25519SharedSize+MLKEMSharedSize)
	ikm = append(ikm, ssX25519...)
	ikm = append(ikm, ssMLKEM...)

	info := []byte(hkdfInfoPrefix + context)
	r := hkdf.New(sha512.New, ikm, saltSum[:], info)

	out := new([SessionSecretSize]byte)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return nil, err
	}
	return out, nil
}

// SignedMessage produces the canonical byte string that hybrid signers and
// verifiers agree on for a given artifact. The returned bytes embed the
// SigMessagePrefix domain separator, the artifact payload, and the
// SHA-512 hash of both long-term public keys. Hashing the keys into the
// signed bytes binds signatures to the specific (Ed25519, ML-DSA-65)
// identity pair: an attacker cannot substitute either half without
// invalidating the signature.
//
// See contracts/hybrid-combiner.md.
func SignedMessage(payload, edPub, pqPub []byte) []byte {
	var keyMaterial []byte
	keyMaterial = append(keyMaterial, edPub...)
	keyMaterial = append(keyMaterial, pqPub...)
	keyHash := sha512.Sum512(keyMaterial)

	out := make([]byte, 0, len(SigMessagePrefix)+len(payload)+len(keyHash))
	out = append(out, []byte(SigMessagePrefix)...)
	out = append(out, payload...)
	out = append(out, keyHash[:]...)
	return out
}
