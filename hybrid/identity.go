// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/oluies/neverlur/pqkem"
	"github.com/oluies/neverlur/pqsig"
)

// HybridIdentity is the paired (classical, post-quantum) long-term
// identity used by guardians, mixers, PKG, CDN, coordinator, and clients.
//
// Three primitives travel together:
//   - EdPub / EdPriv  — Ed25519 (classical signing).
//   - PQPub / PQPriv  — ML-DSA-65 (post-quantum signing). Deterministically
//     derived from the Ed25519 seed via pqsig.DeriveFromEd25519Seed
//     (research.md R4).
//   - MLKEMPub / MLKEMPriv — ML-KEM-768 (long-term post-quantum KEM key,
//     used as the recipient half of the static-ephemeral hybrid friend-
//     request handshake in docs/wire-introduction-v2.md option F).
//     Deterministically derived from the Ed25519 seed via
//     pqkem.DeriveFromEd25519Seed under a distinct domain-separation
//     label, so the ML-KEM and ML-DSA seed material is independent.
//
// All three halves are bound to the Ed25519 seed at generation time; the
// bindings are re-verified on every load via VerifyBinding.
type HybridIdentity struct {
	EdPub     ed25519.PublicKey
	EdPriv    ed25519.PrivateKey // optional; absent for verify-only roles
	PQPub     *pqsig.PublicKey
	PQPriv    *pqsig.PrivateKey // optional; absent for verify-only roles
	MLKEMPub  *pqkem.PublicKey
	MLKEMPriv *pqkem.PrivateKey // optional; absent for verify-only roles
	Created   time.Time
}

// HybridIdentityPublic is the verify-only half of a HybridIdentity.
// It is the form exchanged on the wire and stored in other parties'
// records of "who is who".
type HybridIdentityPublic struct {
	EdPub    ed25519.PublicKey
	PQPub    *pqsig.PublicKey
	MLKEMPub *pqkem.PublicKey
}

var (
	// ErrBindingFailed indicates the identity's PQ half was not the one
	// the R4 binding derives from the Ed25519 seed. Either the file is
	// corrupted, was hand-edited, or was produced by an incompatible
	// implementation.
	ErrBindingFailed = errors.New("hybrid: pq identity binding failed; identity material is invalid")

	// ErrIdentityIncomplete indicates a required field is missing.
	ErrIdentityIncomplete = errors.New("hybrid: incomplete identity material")

	// ErrNoPrivateKey indicates a signing operation was attempted on a
	// verify-only identity.
	ErrNoPrivateKey = errors.New("hybrid: identity has no private key material")
)

// GenerateHybridIdentity produces a fresh hybrid identity by generating
// a new Ed25519 keypair and deriving the bound ML-DSA-65 and
// ML-KEM-768 counterparts.
func GenerateHybridIdentity() (*HybridIdentity, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hybrid: ed25519 keygen: %w", err)
	}
	return hybridIdentityFromEd25519Pair(edPub, edPriv)
}

// HybridIdentityFromEd25519Seed reconstructs a hybrid identity from an
// existing 32-byte Ed25519 seed. This is the path taken when an existing
// pre-PQ deployment upgrades: each principal's existing Ed25519 seed is
// preserved, and both PQ counterparts (ML-DSA-65 and ML-KEM-768) are
// derived deterministically.
func HybridIdentityFromEd25519Seed(edSeed []byte) (*HybridIdentity, error) {
	if len(edSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hybrid: ed25519 seed length %d, want %d", len(edSeed), ed25519.SeedSize)
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("hybrid: ed25519 public-key type assertion failed")
	}
	return hybridIdentityFromEd25519Pair(edPub, edPriv)
}

// hybridIdentityFromEd25519Pair is the shared back-end for
// GenerateHybridIdentity and HybridIdentityFromEd25519Seed. It derives
// both PQ halves and assembles the identity.
func hybridIdentityFromEd25519Pair(edPub ed25519.PublicKey, edPriv ed25519.PrivateKey) (*HybridIdentity, error) {
	pqPub, pqPriv, err := pqsig.DeriveFromEd25519Seed(edPriv.Seed())
	if err != nil {
		return nil, fmt.Errorf("hybrid: pqsig derivation: %w", err)
	}
	mlkemPub, mlkemPriv, err := pqkem.DeriveFromEd25519Seed(edPriv.Seed())
	if err != nil {
		return nil, fmt.Errorf("hybrid: pqkem derivation: %w", err)
	}
	return &HybridIdentity{
		EdPub:     edPub,
		EdPriv:    edPriv,
		PQPub:     pqPub,
		PQPriv:    pqPriv,
		MLKEMPub:  mlkemPub,
		MLKEMPriv: mlkemPriv,
		Created:   time.Now().UTC(),
	}, nil
}

// VerifyBinding re-runs the R4 derivations from the identity's Ed25519
// seed and confirms they produce the same ML-DSA-65 and ML-KEM-768
// public keys. This must succeed on every load; a failure means the
// on-disk material has been tampered with or was produced by an
// incompatible implementation.
//
// Returns ErrBindingFailed if either derivation does not match.
// Returns ErrIdentityIncomplete if the identity has no Ed25519 private
// key (and so no seed to re-derive from); verify-only identities cannot
// be binding-checked locally and must be trusted on the basis of their
// source (e.g. a signed config).
func (id *HybridIdentity) VerifyBinding() error {
	if id == nil || id.EdPriv == nil || id.PQPub == nil || id.MLKEMPub == nil {
		return ErrIdentityIncomplete
	}
	derivedPQPub, _, err := pqsig.DeriveFromEd25519Seed(id.EdPriv.Seed())
	if err != nil {
		return fmt.Errorf("hybrid: re-deriving pqsig key: %w", err)
	}
	if !bytes.Equal(pqsig.PackPublicKey(derivedPQPub), pqsig.PackPublicKey(id.PQPub)) {
		return ErrBindingFailed
	}
	derivedMLKEMPub, _, err := pqkem.DeriveFromEd25519Seed(id.EdPriv.Seed())
	if err != nil {
		return fmt.Errorf("hybrid: re-deriving pqkem key: %w", err)
	}
	if !bytes.Equal(pqkem.PackPublicKey(derivedMLKEMPub), pqkem.PackPublicKey(id.MLKEMPub)) {
		return ErrBindingFailed
	}
	return nil
}

// Public returns the verify-only view of this identity.
func (id *HybridIdentity) Public() *HybridIdentityPublic {
	if id == nil {
		return nil
	}
	return &HybridIdentityPublic{
		EdPub:    append(ed25519.PublicKey(nil), id.EdPub...),
		PQPub:    id.PQPub,
		MLKEMPub: id.MLKEMPub,
	}
}

// Equal returns true iff all three halves of two hybrid identities are
// byte-identical at the public level. Used by edTLS peer verification
// and by the friend-request initiator before encapsulating to a peer's
// long-term ML-KEM key.
func (a *HybridIdentityPublic) Equal(b *HybridIdentityPublic) bool {
	if a == nil || b == nil {
		return false
	}
	if !bytes.Equal(a.EdPub, b.EdPub) {
		return false
	}
	if a.PQPub == nil || b.PQPub == nil {
		return false
	}
	if !bytes.Equal(pqsig.PackPublicKey(a.PQPub), pqsig.PackPublicKey(b.PQPub)) {
		return false
	}
	if a.MLKEMPub == nil || b.MLKEMPub == nil {
		return false
	}
	return bytes.Equal(pqkem.PackPublicKey(a.MLKEMPub), pqkem.PackPublicKey(b.MLKEMPub))
}
