// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

// NOTE: this test file lives in package `neverlur`, which transitively
// imports vuvuzela.io/crypto/bls -> bn256. The bn256 package ships
// hand-rolled x86_64-only assembly that does not compile on arm64
// (specifically not on Apple Silicon). As a result this test cannot be
// run locally on darwin/arm64; it runs in CI on linux/amd64.
//
// All other test layers established by US1 (keywheel/keywheel_hybrid_test.go,
// hybrid/handshake_test.go, hybrid/combiner_test.go) run on arm64
// without issue.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/pqkem"
)

// TestHybridKeywheelSeedAgreement: both sides of a hybrid friend-request
// handshake (initiator and responder), feeding the same handshake
// material into hybridKeywheelSeed, MUST derive the same 32-byte seed.
// This is the foundational agreement property US1 establishes; US2's
// wire-format switch will produce the exact same byte stream on the
// wire and rely on this property to bring the two ends into sync.
func TestHybridKeywheelSeedAgreement(t *testing.T) {
	// Initiator's X25519 keypair.
	var initX25519Priv [32]byte
	if _, err := rand.Read(initX25519Priv[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	initX25519Priv[0] &= 248
	initX25519Priv[31] &= 127
	initX25519Priv[31] |= 64
	initX25519Pub, err := curve25519.X25519(initX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive initX25519Pub: %v", err)
	}
	var initX25519PubArr [32]byte
	copy(initX25519PubArr[:], initX25519Pub)

	// Responder's X25519 keypair.
	var respX25519Priv [32]byte
	if _, err := rand.Read(respX25519Priv[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	respX25519Priv[0] &= 248
	respX25519Priv[31] &= 127
	respX25519Priv[31] |= 64
	respX25519Pub, err := curve25519.X25519(respX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive respX25519Pub: %v", err)
	}
	var respX25519PubArr [32]byte
	copy(respX25519PubArr[:], respX25519Pub)

	// Initiator's ML-KEM keypair.
	initMLKEMPub, initMLKEMPriv, err := pqkem.GenerateKey()
	if err != nil {
		t.Fatalf("pqkem.GenerateKey: %v", err)
	}
	initMLKEMPubBytes := pqkem.PackPublicKey(initMLKEMPub)

	// Responder runs Encapsulate against the initiator's ML-KEM pub.
	mlkemCT, respMLKEMShared, err := pqkem.Encapsulate(initMLKEMPub)
	if err != nil {
		t.Fatalf("pqkem.Encapsulate: %v", err)
	}

	// Initiator runs Decapsulate to recover the same shared secret.
	initMLKEMShared, err := pqkem.Decapsulate(initMLKEMPriv, mlkemCT)
	if err != nil {
		t.Fatalf("pqkem.Decapsulate: %v", err)
	}
	if !bytes.Equal(initMLKEMShared, respMLKEMShared) {
		t.Fatalf("ML-KEM shared secrets disagree (this would indicate a CIRCL bug, not US1)")
	}

	const dialingRound uint32 = 99

	// === Responder side derivation ===
	// The responder calls hybridKeywheelSeed with its OWN X25519 private,
	// the INITIATOR's X25519 pub, and the responder's own X25519 pub
	// (for the transcript). The mlkemSS is from Encapsulate; mlkemPub is
	// the initiator's; mlkemCT is what the responder just produced.
	respSeed, err := hybridKeywheelSeed(
		respX25519Priv, initX25519PubArr, respX25519PubArr,
		respMLKEMShared,
		initMLKEMPubBytes,
		mlkemCT,
		dialingRound,
	)
	if err != nil {
		t.Fatalf("responder hybridKeywheelSeed: %v", err)
	}

	// === Initiator side derivation ===
	// IMPORTANT: the initiator passes (initX25519Pub, respX25519Pub) as
	// the (initX25519Pub, respX25519Pub) transcript pair so both sides
	// hash the same byte string. The local vs peer X25519 keys differ;
	// the transcript pair does not.
	initSeed, err := hybridKeywheelSeed(
		initX25519Priv, respX25519PubArr, initX25519PubArr,
		initMLKEMShared,
		initMLKEMPubBytes,
		mlkemCT,
		dialingRound,
	)
	if err != nil {
		t.Fatalf("initiator hybridKeywheelSeed: %v", err)
	}

	// NOTE: in the current additive design, both sides MUST pass the
	// transcript pair in the same canonical order (initX25519Pub first,
	// respX25519Pub second). The transcript builder does not symmetrize
	// for us; the caller (genIntro / decodeAddFriendMessage in the
	// US1+US2 joint commit) is responsible for arranging the arguments
	// so the byte string is identical on both sides.
	if !bytes.Equal(initSeed[:], respSeed[:]) {
		t.Fatalf("hybridKeywheelSeed disagreement between init and resp:\n  init %x\n  resp %x", initSeed[:], respSeed[:])
	}

	// Sanity: the seed must be different from either input shared secret.
	initX25519Shared, err := curve25519.X25519(initX25519Priv[:], respX25519Pub)
	if err != nil {
		t.Fatalf("classical ECDH: %v", err)
	}
	if bytes.Equal(initSeed[:], initX25519Shared) {
		t.Fatal("hybrid seed equals raw classical ECDH shared secret")
	}
	if bytes.Equal(initSeed[:], initMLKEMShared) {
		t.Fatal("hybrid seed equals raw ML-KEM shared secret")
	}
}

// TestHybridKeywheelTranscriptDeterministic asserts the transcript
// builder is byte-deterministic for fixed inputs. Combined with the
// agreement test, this proves both sides will hash the same byte string
// when invoked with matching arguments.
func TestHybridKeywheelTranscriptDeterministic(t *testing.T) {
	var initX, respX [32]byte
	for i := range initX {
		initX[i] = byte(i)
		respX[i] = byte(i + 32)
	}
	mlkemPub := make([]byte, pqkem.PublicKeySize)
	for i := range mlkemPub {
		mlkemPub[i] = byte(i & 0x7f)
	}
	mlkemCT := make([]byte, pqkem.CiphertextSize)
	for i := range mlkemCT {
		mlkemCT[i] = byte((i * 3) & 0xff)
	}
	a := buildKeywheelTranscript(initX, respX, mlkemPub, mlkemCT, 12345)
	b := buildKeywheelTranscript(initX, respX, mlkemPub, mlkemCT, 12345)
	if !bytes.Equal(a, b) {
		t.Fatal("transcript builder is not deterministic on identical inputs")
	}
	c := buildKeywheelTranscript(initX, respX, mlkemPub, mlkemCT, 12346)
	if bytes.Equal(a, c) {
		t.Fatal("transcript builder did not bind dialingRound")
	}
}
