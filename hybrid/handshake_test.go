// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/pqkem"
)

// TestFoundationalHandshakeAgreement composes the foundational primitive
// stack — X25519 ECDH + ML-KEM-768 Encap/Decap + CombineKEM — end to end
// without any of the protocol-layer code that US1/US2 will eventually
// build on top.
//
// The two sides ("initiator" and "responder") run the full hybrid KEM and
// MUST derive the same 32-byte session secret. This proves the
// foundational APIs compose correctly before the friend-request path is
// wired through in US1.
func TestFoundationalHandshakeAgreement(t *testing.T) {
	// === Setup: long-term identities. ===
	initiatorID, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("initiator identity: %v", err)
	}
	responderID, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("responder identity: %v", err)
	}

	// === Initiator side ===

	// Ephemeral X25519 keypair.
	var initX25519Priv [32]byte
	if _, err := rand.Read(initX25519Priv[:]); err != nil {
		t.Fatalf("read initX25519Priv: %v", err)
	}
	// Clamp per RFC 7748 §5 (curve25519.X25519 expects clamped scalar).
	initX25519Priv[0] &= 248
	initX25519Priv[31] &= 127
	initX25519Priv[31] |= 64
	initX25519Pub, err := curve25519.X25519(initX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive initX25519Pub: %v", err)
	}

	// Ephemeral ML-KEM-768 keypair.
	initMLKEMPub, initMLKEMPriv, err := pqkem.GenerateKey()
	if err != nil {
		t.Fatalf("initMLKEMPub: %v", err)
	}

	// === Responder side ===

	// Ephemeral X25519 keypair.
	var respX25519Priv [32]byte
	if _, err := rand.Read(respX25519Priv[:]); err != nil {
		t.Fatalf("read respX25519Priv: %v", err)
	}
	respX25519Priv[0] &= 248
	respX25519Priv[31] &= 127
	respX25519Priv[31] |= 64
	respX25519Pub, err := curve25519.X25519(respX25519Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive respX25519Pub: %v", err)
	}

	// Encapsulate to the initiator's ML-KEM public key.
	mlkemCT, respMLKEMShared, err := pqkem.Encapsulate(initMLKEMPub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// Responder's X25519 ECDH with the initiator's public key.
	respX25519Shared, err := curve25519.X25519(respX25519Priv[:], initX25519Pub)
	if err != nil {
		t.Fatalf("responder X25519: %v", err)
	}

	// Build a transcript binding both halves of both identities and the
	// public ephemerals. The exact layout will be standardized in US1;
	// here we only need agreement between the two sides on the bytes.
	transcript := buildHandshakeTranscript(
		initiatorID.Public(), responderID.Public(),
		initX25519Pub, respX25519Pub,
		initMLKEMPub, mlkemCT,
	)

	// Responder derives the session secret.
	respSecret, err := CombineKEM(ContextFriendRequest, transcript, respX25519Shared, respMLKEMShared)
	if err != nil {
		t.Fatalf("responder CombineKEM: %v", err)
	}

	// === Back on the initiator: derive the same secret ===

	initX25519Shared, err := curve25519.X25519(initX25519Priv[:], respX25519Pub)
	if err != nil {
		t.Fatalf("initiator X25519: %v", err)
	}
	initMLKEMShared, err := pqkem.Decapsulate(initMLKEMPriv, mlkemCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	initSecret, err := CombineKEM(ContextFriendRequest, transcript, initX25519Shared, initMLKEMShared)
	if err != nil {
		t.Fatalf("initiator CombineKEM: %v", err)
	}

	// === Agreement ===

	if !bytes.Equal(initSecret[:], respSecret[:]) {
		t.Fatalf("foundational handshake did not agree:\n  init: %x\n  resp: %x", initSecret[:], respSecret[:])
	}

	// Sanity: components alone are not enough.
	if bytes.Equal(initSecret[:], initX25519Shared) {
		t.Fatal("session secret equals raw classical shared secret")
	}
	if bytes.Equal(initSecret[:], initMLKEMShared) {
		t.Fatal("session secret equals raw PQ shared secret")
	}
}

// buildHandshakeTranscript concatenates everything the two sides agree on
// for the purpose of the CombineKEM transcript. The exact byte order
// shown here is a foundational placeholder; US1 will standardize the
// canonical form (data-model.md E7, contracts/introduction-v2.md).
func buildHandshakeTranscript(
	initID, respID *HybridIdentityPublic,
	initX25519Pub, respX25519Pub []byte,
	initMLKEMPub *pqkem.PublicKey, mlkemCT []byte,
) []byte {
	var buf []byte
	buf = append(buf, []byte("hybrid-foundational-handshake-v1")...)
	buf = append(buf, initID.EdPub...)
	buf = append(buf, respID.EdPub...)
	buf = append(buf, initX25519Pub...)
	buf = append(buf, respX25519Pub...)
	buf = append(buf, pqkem.PackPublicKey(initMLKEMPub)...)
	buf = append(buf, mlkemCT...)
	return buf
}
