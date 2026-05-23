// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pqkem"
)

// hybridKeywheelSeed derives the 32-byte seed handed to keywheel.Wheel.Put
// for a new friendship, using the hybrid combiner under the option-F
// static-ephemeral design (docs/wire-introduction-v2.md).
//
// Per-friendship, each side has THREE shared-secret contributions:
//
//   - ssX25519: symmetric ECDH over the per-friend-request X25519
//     ephemerals each side independently generated.
//   - ssAliceEncap: the result of Alice's Encapsulate to Bob's long-term
//     ML-KEM-768 pub. Alice knows this directly (she computed it); Bob
//     recovers it via Decapsulate against his own long-term ML-KEM priv.
//   - ssBobEncap: symmetric — Bob's Encap to Alice's long-term ML-KEM pub.
//
// Both sides fold the three contributions into the combiner in a
// canonical Alpha-sorted order over the two long-term ML-KEM public
// keys so they agree byte-for-byte regardless of which side is computing
// the seed. The combiner is hybrid.CombineKEM with ContextKeywheelSeed;
// the second secret passed to CombineKEM is the concatenation of the
// two ML-KEM shared secrets in canonical order (the combiner's two-PQ
// extension keeps the existing one-arg interface — see the design note
// "Open issues" section).
//
// Inputs:
//
//   - x25519Priv / theirX25519Pub: this side's per-friend-request X25519
//     ephemeral private and the peer's X25519 ephemeral public, used to
//     derive ssX25519.
//   - myX25519Pub / theirX25519Pub: also bound into the transcript so
//     both sides hash the same byte string.
//   - ssOutgoing: this side's locally-computed ML-KEM shared secret
//     (from Encapsulate(peerLongTermMLKEMPub)). 32 bytes.
//   - ssIncoming: the ML-KEM shared secret recovered by decapsulating
//     the peer's ciphertext under this side's long-term ML-KEM priv.
//     32 bytes.
//   - myLongTermMLKEMPub / peerLongTermMLKEMPub: both long-term ML-KEM
//     public keys, used for canonical ordering and transcript binding.
//   - myMLKEMCT / peerMLKEMCT: both per-friendship MLKEMCiphertext blobs
//     exchanged on the wire, bound into the transcript so a
//     transcript-replay attack against either party is detected.
//   - dialingRound: the dialing round the friend request belongs to,
//     bound into the transcript.
//
// The output is suitable as the *[32]byte seed input to
// keywheel.Wheel.Put.
func hybridKeywheelSeed(
	x25519Priv, theirX25519Pub, myX25519Pub [32]byte,
	ssOutgoing, ssIncoming []byte,
	myLongTermMLKEMPub, peerLongTermMLKEMPub []byte,
	myMLKEMCT, peerMLKEMCT []byte,
	dialingRound uint32,
) (*[32]byte, error) {
	ssX, err := curve25519.X25519(x25519Priv[:], theirX25519Pub[:])
	if err != nil {
		return nil, err
	}

	// Canonical Alpha order so both peers fold the same bytes into the
	// transcript and the combiner regardless of which side is computing.
	lt1, lt2, ct1, ct2, ssEncap1, ssEncap2, x1, x2 := canonicalAlpha(
		myLongTermMLKEMPub, peerLongTermMLKEMPub,
		myMLKEMCT, peerMLKEMCT,
		ssOutgoing, ssIncoming,
		myX25519Pub, theirX25519Pub,
	)

	transcript := buildKeywheelTranscript(x1, x2, lt1, lt2, ct1, ct2, dialingRound)

	// Concatenate the two ML-KEM shared secrets in canonical order
	// before handing them to the single-PQ-arg combiner. The combiner
	// hashes its ssMLKEM input as opaque bytes; concatenation preserves
	// the half-compromise property as long as each individual ssEncap
	// is unforgeable, which is the ML-KEM IND-CCA guarantee.
	ssMLKEMCombined := make([]byte, 0, len(ssEncap1)+len(ssEncap2))
	ssMLKEMCombined = append(ssMLKEMCombined, ssEncap1...)
	ssMLKEMCombined = append(ssMLKEMCombined, ssEncap2...)

	return hybrid.CombineKEMConcat(hybrid.ContextKeywheelSeed, transcript, ssX, ssMLKEMCombined)
}

// canonicalAlpha sorts the (myLTMLKEMPub, peerLTMLKEMPub) pair lexically
// and returns all parallel parameters reordered to match. This lets
// both sides of a friendship feed the combiner the same byte string
// regardless of which side is computing.
func canonicalAlpha(
	myLT, peerLT []byte,
	myCT, peerCT []byte,
	mySS, peerSS []byte,
	myX25519Pub, peerX25519Pub [32]byte,
) (lt1, lt2, ct1, ct2, ss1, ss2 []byte, x1, x2 [32]byte) {
	if bytes.Compare(myLT, peerLT) <= 0 {
		return myLT, peerLT, myCT, peerCT, mySS, peerSS, myX25519Pub, peerX25519Pub
	}
	return peerLT, myLT, peerCT, myCT, peerSS, mySS, peerX25519Pub, myX25519Pub
}

// buildKeywheelTranscript assembles the byte string fed to the combiner
// as the HKDF salt input under the option-F layout. The byte order is:
//
//	"neverlur-keywheel-seed-v2"        (24 bytes)
//	|| first X25519 pub  (canonical)   (32)
//	|| second X25519 pub (canonical)   (32)
//	|| first  LT ML-KEM pub (canonical)  (pqkem.PublicKeySize)
//	|| second LT ML-KEM pub (canonical)  (pqkem.PublicKeySize)
//	|| first  MLKEM CT (canonical)       (pqkem.CiphertextSize)
//	|| second MLKEM CT (canonical)       (pqkem.CiphertextSize)
//	|| big-endian uint32 dialing round (4)
//
// Canonical Alpha ordering is performed by canonicalAlpha based on the
// two long-term ML-KEM public keys (lex compare). The same ordering is
// then applied to the matching X25519 pubs and CTs so the byte string
// is reproducible regardless of which side is computing.
func buildKeywheelTranscript(
	x1, x2 [32]byte,
	lt1, lt2 []byte,
	ct1, ct2 []byte,
	dialingRound uint32,
) []byte {
	const prefix = "neverlur-keywheel-seed-v2"
	out := make([]byte, 0, len(prefix)+32+32+pqkem.PublicKeySize*2+pqkem.CiphertextSize*2+4)
	out = append(out, []byte(prefix)...)
	out = append(out, x1[:]...)
	out = append(out, x2[:]...)
	out = append(out, lt1...)
	out = append(out, lt2...)
	out = append(out, ct1...)
	out = append(out, ct2...)
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], dialingRound)
	out = append(out, rb[:]...)
	return out
}
