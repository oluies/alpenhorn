// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/oluies/neverlur/pqsig"
)

// HybridSignature is the paired (Ed25519, ML-DSA-65) signature used by
// SignedConfig v2 (data-model.md E4 and contracts/signed-config-v2.md).
// Both halves are fixed-width for the chosen parameter sets so the
// concatenated encoding has a known length and no separator ambiguity.
//
// The Ed25519 half is 64 bytes; the ML-DSA-65 half is pqsig.SignatureSize
// (3309) bytes. Total wire size: 3373 bytes.
type HybridSignature struct {
	Ed [HybridSignatureEdSize]byte
	PQ [HybridSignaturePQSize]byte
}

// HybridSignatureEdSize is the size in bytes of the classical (Ed25519)
// half of a HybridSignature.
const HybridSignatureEdSize = 64

// HybridSignaturePQSize is the size in bytes of the post-quantum
// (ML-DSA-65) half of a HybridSignature.
const HybridSignaturePQSize = pqsig.SignatureSize

// HybridSignatureSize is the total on-wire size of a HybridSignature.
const HybridSignatureSize = HybridSignatureEdSize + HybridSignaturePQSize

// ErrHybridSignatureSize indicates that decoded HybridSignature bytes had
// the wrong total length.
var ErrHybridSignatureSize = errors.New("config: hybrid signature must be 3373 bytes (64 ed25519 || 3309 ml-dsa-65)")

// Bytes returns the canonical concatenated encoding (Ed || PQ).
func (s *HybridSignature) Bytes() []byte {
	out := make([]byte, HybridSignatureSize)
	copy(out[:HybridSignatureEdSize], s.Ed[:])
	copy(out[HybridSignatureEdSize:], s.PQ[:])
	return out
}

// UnmarshalBytes parses the canonical concatenated encoding.
func (s *HybridSignature) UnmarshalBytes(b []byte) error {
	if len(b) != HybridSignatureSize {
		return fmt.Errorf("%w: got %d bytes", ErrHybridSignatureSize, len(b))
	}
	copy(s.Ed[:], b[:HybridSignatureEdSize])
	copy(s.PQ[:], b[HybridSignatureEdSize:])
	return nil
}

// MarshalJSON encodes a HybridSignature as a base64 string carrying the
// 3373-byte concatenation. Using a string (not a struct) keeps the wire
// schema compact and makes the "both halves travel together" invariant
// structural — there is no way to send only one half.
func (s HybridSignature) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(s.Bytes()))
}

// UnmarshalJSON decodes the base64-encoded concatenation produced by
// MarshalJSON.
func (s *HybridSignature) UnmarshalJSON(data []byte) error {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return fmt.Errorf("config: decode hybrid signature base64: %w", err)
	}
	return s.UnmarshalBytes(raw)
}
