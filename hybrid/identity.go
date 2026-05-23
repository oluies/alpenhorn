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

	"github.com/oluies/neverlur/pqsig"
)

// HybridIdentity is the paired (classical, post-quantum) long-term
// identity used by guardians, mixers, PKG, CDN, coordinator, and clients.
// The two halves are bound at generation by deriving the ML-DSA-65
// keypair from the Ed25519 seed (research.md R4); the binding is
// re-verified on every load via VerifyBinding.
type HybridIdentity struct {
	EdPub   ed25519.PublicKey
	EdPriv  ed25519.PrivateKey // optional; absent for verify-only roles
	PQPub   *pqsig.PublicKey
	PQPriv  *pqsig.PrivateKey // optional; absent for verify-only roles
	Created time.Time
}

// HybridIdentityPublic is the verify-only half of a HybridIdentity.
// It is the form exchanged on the wire and stored in other parties'
// records of "who is who".
type HybridIdentityPublic struct {
	EdPub ed25519.PublicKey
	PQPub *pqsig.PublicKey
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
// a new Ed25519 keypair and deriving the bound ML-DSA-65 counterpart.
func GenerateHybridIdentity() (*HybridIdentity, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hybrid: ed25519 keygen: %w", err)
	}
	pqPub, pqPriv, err := pqsig.DeriveFromEd25519Seed(edPriv.Seed())
	if err != nil {
		return nil, fmt.Errorf("hybrid: pq derivation: %w", err)
	}
	return &HybridIdentity{
		EdPub:   edPub,
		EdPriv:  edPriv,
		PQPub:   pqPub,
		PQPriv:  pqPriv,
		Created: time.Now().UTC(),
	}, nil
}

// HybridIdentityFromEd25519Seed reconstructs a hybrid identity from an
// existing 32-byte Ed25519 seed. This is the path taken when an existing
// pre-PQ deployment upgrades: each principal's existing Ed25519 seed is
// preserved, and the PQ counterpart is derived deterministically.
func HybridIdentityFromEd25519Seed(edSeed []byte) (*HybridIdentity, error) {
	if len(edSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hybrid: ed25519 seed length %d, want %d", len(edSeed), ed25519.SeedSize)
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("hybrid: ed25519 public-key type assertion failed")
	}
	pqPub, pqPriv, err := pqsig.DeriveFromEd25519Seed(edSeed)
	if err != nil {
		return nil, err
	}
	return &HybridIdentity{
		EdPub:   edPub,
		EdPriv:  edPriv,
		PQPub:   pqPub,
		PQPriv:  pqPriv,
		Created: time.Now().UTC(),
	}, nil
}

// VerifyBinding re-runs the R4 derivation from the identity's Ed25519
// seed and confirms it produces the same ML-DSA-65 public key. This
// must succeed on every load; a failure means the on-disk material has
// been tampered with or was produced by an incompatible implementation.
//
// Returns ErrBindingFailed if the derivation does not match.
// Returns ErrIdentityIncomplete if the identity has no Ed25519 private
// key (and so no seed to re-derive from); verify-only identities cannot
// be binding-checked locally and must be trusted on the basis of their
// source (e.g. a signed config).
func (id *HybridIdentity) VerifyBinding() error {
	if id == nil || id.EdPriv == nil || id.PQPub == nil {
		return ErrIdentityIncomplete
	}
	derivedPub, _, err := pqsig.DeriveFromEd25519Seed(id.EdPriv.Seed())
	if err != nil {
		return fmt.Errorf("hybrid: re-deriving pq key: %w", err)
	}
	if !bytes.Equal(pqsig.PackPublicKey(derivedPub), pqsig.PackPublicKey(id.PQPub)) {
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
		EdPub: append(ed25519.PublicKey(nil), id.EdPub...),
		PQPub: id.PQPub,
	}
}

// Equal returns true iff both halves of two hybrid identities are
// byte-identical at the public level. Used by edTLS peer verification.
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
	return bytes.Equal(pqsig.PackPublicKey(a.PQPub), pqsig.PackPublicKey(b.PQPub))
}
