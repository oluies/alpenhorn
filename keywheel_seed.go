// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

import (
	"encoding/binary"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqkem"
)

// hybridKeywheelSeed derives the 32-byte seed handed to keywheel.Wheel.Put
// for a new friendship, using the hybrid combiner over an X25519 ECDH
// shared secret and an ML-KEM-768 shared secret.
//
// Inputs:
//
//   - x25519Priv / theirX25519Pub — the local party's X25519 ephemeral
//     private key (32 bytes) and the peer's X25519 ephemeral public
//     key (32 bytes). Together they yield the classical shared secret
//     via curve25519.X25519.
//   - x25519MyPub — the local party's X25519 public key, bound into the
//     transcript so both sides hash the same byte string regardless of
//     which side computes which half.
//   - mlkemSS — the ML-KEM-768 shared secret (32 bytes). The initiator
//     obtains this via pqkem.Decapsulate against its
//     sentFriendRequest.MLKEMPrivateKey and the responder-supplied
//     ciphertext; the responder obtains it via pqkem.Encapsulate against
//     the initiator-supplied public key.
//   - mlkemPub — the initiator's ML-KEM-768 public key (PublicKeySize
//     bytes), bound into the transcript so transcript-replay attacks
//     against either party are detected.
//   - mlkemCT — the ML-KEM-768 ciphertext that produced mlkemSS, bound
//     into the transcript for the same reason.
//   - dialingRound — the dialing round number the friend request belongs
//     to, bound into the transcript so two friend requests in different
//     rounds with otherwise identical material cannot collide.
//
// The output is suitable as the *[32]byte seed input to
// keywheel.Wheel.Put. The wheel's ratchet (HMAC-SHA256 chain) consumes
// the output transparently.
//
// See research.md R3 and contracts/hybrid-combiner.md for the combiner
// design. The transcript construction here is the canonical form for
// the keywheel context; it does NOT include long-term identity halves
// (those are bound by the introductionV2 signature in US2).
func hybridKeywheelSeed(
	x25519Priv, theirX25519Pub, x25519MyPub [32]byte,
	mlkemSS []byte,
	mlkemPub []byte,
	mlkemCT []byte,
	dialingRound uint32,
) (*[32]byte, error) {
	ssX, err := curve25519.X25519(x25519Priv[:], theirX25519Pub[:])
	if err != nil {
		return nil, err
	}
	transcript := buildKeywheelTranscript(x25519MyPub, theirX25519Pub, mlkemPub, mlkemCT, dialingRound)
	return hybrid.CombineKEM(hybrid.ContextKeywheelSeed, transcript, ssX, mlkemSS)
}

// buildKeywheelTranscript assembles the byte string fed to the combiner
// as the HKDF salt input. The byte layout is:
//
//	"neverlur-keywheel-seed-v1"        (24 bytes)
//	|| initiator X25519 pub            (32)
//	|| responder X25519 pub            (32)
//	|| initiator ML-KEM-768 pub        (pqkem.PublicKeySize = 1184)
//	|| ML-KEM-768 ciphertext           (pqkem.CiphertextSize = 1088)
//	|| big-endian uint32 dialing round (4)
//
// The "initiator" perspective is whichever side generated the original
// friend request; the same byte string is reproducible by both peers.
// myPub vs theirPub ordering at the call site MUST swap on the
// responder side so that initiator/responder bytes appear in the same
// slots regardless of which peer is computing the seed.
func buildKeywheelTranscript(
	initX25519Pub, respX25519Pub [32]byte,
	initMLKEMPub []byte,
	mlkemCT []byte,
	dialingRound uint32,
) []byte {
	const prefix = "neverlur-keywheel-seed-v1"
	out := make([]byte, 0, len(prefix)+32+32+pqkem.PublicKeySize+pqkem.CiphertextSize+4)
	out = append(out, []byte(prefix)...)
	out = append(out, initX25519Pub[:]...)
	out = append(out, respX25519Pub[:]...)
	out = append(out, initMLKEMPub...)
	out = append(out, mlkemCT...)
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], dialingRound)
	out = append(out, rb[:]...)
	return out
}
