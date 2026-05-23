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
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqkem"
)

// TestHybridKeywheelSeedAgreement: both sides of a hybrid friend-request
// handshake under option F (static-ephemeral, single round) derive the
// same 32-byte keywheel seed.
//
// Per side, the inputs are:
//   - this side's X25519 ephemeral priv + the peer's X25519 ephemeral pub
//   - this side's locally-computed ML-KEM shared secret (from
//     Encapsulate(peerLongTermMLKEMPub))
//   - the peer's MLKEM ciphertext (received via intro), decapsulated
//     against this side's long-term ML-KEM priv to recover the peer's
//     locally-computed shared secret
//   - both long-term ML-KEM pubs and both MLKEM CTs, for transcript
//     binding
//
// The canonical Alpha-sorted order over the two long-term ML-KEM pubs
// inside hybridKeywheelSeed makes both sides feed the combiner the same
// byte string regardless of which side is computing.
func TestHybridKeywheelSeedAgreement(t *testing.T) {
	// === Long-term identities ===
	aliceID, err := hybrid.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("Alice identity: %v", err)
	}
	bobID, err := hybrid.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("Bob identity: %v", err)
	}
	aliceLTBytes := pqkem.PackPublicKey(aliceID.MLKEMPub)
	bobLTBytes := pqkem.PackPublicKey(bobID.MLKEMPub)

	// === Per-friend-request X25519 ephemerals (Alice and Bob) ===
	var aliceX25519Priv, bobX25519Priv [32]byte
	if _, err := rand.Read(aliceX25519Priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(bobX25519Priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for _, k := range []*[32]byte{&aliceX25519Priv, &bobX25519Priv} {
		k[0] &= 248
		k[31] &= 127
		k[31] |= 64
	}
	aliceX25519PubSlice, err := curve25519.X25519(aliceX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("alice X25519 pub: %v", err)
	}
	bobX25519PubSlice, err := curve25519.X25519(bobX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("bob X25519 pub: %v", err)
	}
	var aliceX25519Pub, bobX25519Pub [32]byte
	copy(aliceX25519Pub[:], aliceX25519PubSlice)
	copy(bobX25519Pub[:], bobX25519PubSlice)

	// === Alice's encap to Bob's LT ML-KEM pub ===
	aliceCT, aliceSSOut, err := pqkem.Encapsulate(bobID.MLKEMPub)
	if err != nil {
		t.Fatalf("Alice Encapsulate: %v", err)
	}
	// Bob recovers ssOut by decapsulating with his own LT priv.
	bobSSIn, err := pqkem.Decapsulate(bobID.MLKEMPriv, aliceCT)
	if err != nil {
		t.Fatalf("Bob Decapsulate Alice's CT: %v", err)
	}
	if !bytes.Equal(aliceSSOut, bobSSIn) {
		t.Fatal("Alice's encap shared secret != Bob's decap shared secret")
	}

	// === Bob's encap to Alice's LT ML-KEM pub ===
	bobCT, bobSSOut, err := pqkem.Encapsulate(aliceID.MLKEMPub)
	if err != nil {
		t.Fatalf("Bob Encapsulate: %v", err)
	}
	aliceSSIn, err := pqkem.Decapsulate(aliceID.MLKEMPriv, bobCT)
	if err != nil {
		t.Fatalf("Alice Decapsulate Bob's CT: %v", err)
	}
	if !bytes.Equal(bobSSOut, aliceSSIn) {
		t.Fatal("Bob's encap shared secret != Alice's decap shared secret")
	}

	const dialingRound uint32 = 99

	// === Alice side: derives the seed ===
	aliceSeed, err := hybridKeywheelSeed(
		aliceX25519Priv, bobX25519Pub, aliceX25519Pub,
		aliceSSOut, aliceSSIn,
		aliceLTBytes, bobLTBytes,
		aliceCT, bobCT,
		dialingRound,
	)
	if err != nil {
		t.Fatalf("Alice hybridKeywheelSeed: %v", err)
	}

	// === Bob side: derives the seed (swapped my/peer arguments) ===
	bobSeed, err := hybridKeywheelSeed(
		bobX25519Priv, aliceX25519Pub, bobX25519Pub,
		bobSSOut, bobSSIn,
		bobLTBytes, aliceLTBytes,
		bobCT, aliceCT,
		dialingRound,
	)
	if err != nil {
		t.Fatalf("Bob hybridKeywheelSeed: %v", err)
	}

	if !bytes.Equal(aliceSeed[:], bobSeed[:]) {
		t.Fatalf("Alice and Bob disagree on keywheel seed:\n  Alice %x\n  Bob   %x", aliceSeed[:], bobSeed[:])
	}

	// Sanity: the seed must not equal any individual shared secret.
	if bytes.Equal(aliceSeed[:], aliceSSOut) {
		t.Fatal("seed equals raw Alice-encap shared secret")
	}
	if bytes.Equal(aliceSeed[:], aliceSSIn) {
		t.Fatal("seed equals raw Alice-decap shared secret")
	}
	aliceX25519Shared, _ := curve25519.X25519(aliceX25519Priv[:], bobX25519PubSlice)
	if bytes.Equal(aliceSeed[:], aliceX25519Shared) {
		t.Fatal("seed equals raw classical ECDH")
	}
}

// TestHybridKeywheelTranscriptCanonicalAlpha asserts the transcript is
// computed in the same byte order regardless of which side calls
// hybridKeywheelSeed first — i.e., canonical Alpha sort is applied.
//
// We construct the same friendship setup TWICE, with my/peer arguments
// swapped, and confirm the derived seeds match.
func TestHybridKeywheelTranscriptCanonicalAlpha(t *testing.T) {
	// Build two long-term identities with deterministically chosen
	// MLKEM pubs so the canonical sort always has a stable winner.
	aliceID, _ := hybrid.GenerateHybridIdentity()
	bobID, _ := hybrid.GenerateHybridIdentity()
	aliceLT := pqkem.PackPublicKey(aliceID.MLKEMPub)
	bobLT := pqkem.PackPublicKey(bobID.MLKEMPub)

	// Synthetic data for the per-friendship inputs.
	var x1Priv, x2Priv [32]byte
	rand.Read(x1Priv[:])
	rand.Read(x2Priv[:])
	for _, k := range []*[32]byte{&x1Priv, &x2Priv} {
		k[0] &= 248
		k[31] &= 127
		k[31] |= 64
	}
	x1PubS, _ := curve25519.X25519(x1Priv[:], curve25519.Basepoint)
	x2PubS, _ := curve25519.X25519(x2Priv[:], curve25519.Basepoint)
	var x1Pub, x2Pub [32]byte
	copy(x1Pub[:], x1PubS)
	copy(x2Pub[:], x2PubS)

	ct1, ss1Out, _ := pqkem.Encapsulate(bobID.MLKEMPub)
	ss1In, _ := pqkem.Decapsulate(aliceID.MLKEMPriv, ct1)
	ct2, ss2Out, _ := pqkem.Encapsulate(aliceID.MLKEMPub)
	ss2In, _ := pqkem.Decapsulate(bobID.MLKEMPriv, ct2)
	_ = ss1In
	_ = ss2In

	const round uint32 = 7

	// Call as "I am Alice": myMLKEM=aliceLT, peer=bobLT
	seedA, err := hybridKeywheelSeed(
		x1Priv, x2Pub, x1Pub,
		ss1Out, ss2Out,
		aliceLT, bobLT,
		ct1, ct2,
		round,
	)
	if err != nil {
		t.Fatalf("Alice-perspective: %v", err)
	}

	// Call as "I am Bob": swap every "my" and "peer" argument.
	seedB, err := hybridKeywheelSeed(
		x2Priv, x1Pub, x2Pub,
		ss2Out, ss1Out,
		bobLT, aliceLT,
		ct2, ct1,
		round,
	)
	if err != nil {
		t.Fatalf("Bob-perspective: %v", err)
	}

	if !bytes.Equal(seedA[:], seedB[:]) {
		t.Fatalf("canonical Alpha sort broke: Alice and Bob disagree\n  A %x\n  B %x", seedA[:], seedB[:])
	}
}
