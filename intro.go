// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/oluies/neverlur/addfriend"
	"github.com/oluies/neverlur/hybrid"
	"github.com/oluies/neverlur/pkg"
	"github.com/oluies/neverlur/pqkem"
	"github.com/oluies/neverlur/pqsig"
	"vuvuzela.io/crypto/bls"
)

// Compile-time assertion: addfriend.SizeIntroV2 must match the byte size
// of the introductionV2 wire layout below. addfriend declares it as a
// constant (rather than importing this package, which would create a
// cycle), so this assertion guards against the two drifting apart.
const _ = uint(SizeIntroV2 - addfriend.SizeIntroV2)
const _ = uint(addfriend.SizeIntroV2 - SizeIntroV2)

const (
	sizeIntro = int(unsafe.Sizeof(introduction{}))

	// introductionV2Version is the leading version byte of an on-wire v2
	// introduction (data-model.md E7). Any other leading byte is rejected
	// by the v2 unmarshaler.
	introductionV2Version byte = 2

	// SizeIntroV2 is the fixed on-wire size of an introductionV2 in bytes.
	// See docs/wire-introduction-v2.md for the field-by-field layout.
	//
	// Layout: 1 (Version) + 64 (Username) + 32 (DHPublicKey)
	//       + pqkem.PublicKeySize (1184)
	//       + 4 (DialingRound) + 32 (LongTermKey)
	//       + pqsig.PublicKeySize (1952)
	//       + 64 (Signature) + pqsig.SignatureSize (3309)
	//       + 32 (ServerMultisig) + 21 (reserved padding)
	//       = 6695.
	SizeIntroV2 = 1 + 64 + 32 + pqkem.PublicKeySize + 4 + 32 + pqsig.PublicKeySize + 64 + pqsig.SignatureSize + 32 + 21

	// introductionSigPrefix is the leading domain separator of the byte
	// string covered by both Signature and SignaturePQ.
	introductionSigPrefix = "NeverlurIntroductionV2"
)

// introduction is the legacy classical-only Alpenhorn add-friend
// introduction. Retained while addfriend.go and the rest of the
// add-friend protocol still consume it. A follow-up commit (the
// introduction v2 wire switch) will swap genIntro / decodeAddFriendMessage
// to produce/consume introductionV2 instead, after which this struct
// and its Sign/Verify/Marshal methods will be deleted.
type introduction struct {
	Username       [64]byte
	DHPublicKey    [32]byte
	DialingRound   uint32
	LongTermKey    [32]byte
	Signature      [64]byte
	ServerMultisig [32]byte
}

func (i *introduction) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (i *introduction) UnmarshalBinary(data []byte) error {
	return binary.Read(bytes.NewReader(data), binary.BigEndian, i)
}

func (i *introduction) Verify(serverKeys []*bls.PublicKey) bool {
	longTermKey := ed25519.PublicKey(i.LongTermKey[:])
	msgs := make([][]byte, len(serverKeys))
	for j, key := range serverKeys {
		attestation := &pkg.Attestation{
			AttestKey:       key,
			UserIdentity:    &i.Username,
			UserLongTermKey: longTermKey,
		}
		msgs[j] = attestation.Marshal()
	}
	ok1 := bls.VerifyCompressed(serverKeys, msgs, &i.ServerMultisig)
	ok2 := ed25519.Verify(longTermKey, i.msg(), i.Signature[:])
	return ok1 && ok2
}

func (i *introduction) Sign(key ed25519.PrivateKey) {
	sig := ed25519.Sign(key, i.msg())
	copy(i.Signature[:], sig)
}

func (i *introduction) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("Introduction")
	buf.Write(i.Username[:])
	buf.Write(i.DHPublicKey[:])
	binary.Write(buf, binary.BigEndian, i.DialingRound)
	return buf.Bytes()
}

// ErrIntroV2Version indicates a v2 unmarshaler was handed bytes whose
// leading version byte was not 0x02.
var ErrIntroV2Version = errors.New("neverlur: introduction is not v2")

// ErrIntroV2Size indicates a wrong-sized v2 introduction blob.
var ErrIntroV2Size = errors.New("neverlur: introduction v2 wrong size")

// introductionV2 is the hybrid post-quantum form of an Alpenhorn add-friend
// introduction. See docs/wire-introduction-v2.md for the wire layout and
// docs/wire-introduction-v2.md#signed-message for the signed-message
// construction. Field order and sizes are part of the wire format; do
// not reorder.
//
// Reserved is zero-padding so the encoded length is a multiple of 7,
// which the IBE chunking helper prefers.
type introductionV2 struct {
	Version        byte
	Username       [64]byte
	DHPublicKey    [32]byte
	MLKEMPublicKey [pqkem.PublicKeySize]byte
	DialingRound   uint32
	LongTermKey    [32]byte
	LongTermKeyPQ  [pqsig.PublicKeySize]byte
	Signature      [64]byte
	SignaturePQ    [pqsig.SignatureSize]byte
	ServerMultisig [32]byte
	Reserved       [21]byte
}

// MarshalBinary returns the fixed-width SizeIntroV2-byte canonical
// encoding of i. The encoding always sets Version to introductionV2Version;
// callers that produce v2 introductions through Sign() can rely on this.
func (i *introductionV2) MarshalBinary() ([]byte, error) {
	i.Version = introductionV2Version
	buf := new(bytes.Buffer)
	buf.Grow(SizeIntroV2)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		return nil, err
	}
	if buf.Len() != SizeIntroV2 {
		return nil, fmt.Errorf("neverlur: introductionV2.MarshalBinary produced %d bytes, want %d", buf.Len(), SizeIntroV2)
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary parses the fixed-width SizeIntroV2-byte canonical
// encoding into i. Rejects any input of wrong length, and rejects any
// input whose leading version byte is not introductionV2Version.
//
// The v2 unmarshaler does NOT fall back to v1 on a version mismatch.
// Mixed-version coexistence within a deployment is handled at the
// deployment-coordination layer (US3 cutover), not at the parser layer
// (constitution Principle V: no silent downgrade).
func (i *introductionV2) UnmarshalBinary(data []byte) error {
	if len(data) != SizeIntroV2 {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrIntroV2Size, len(data), SizeIntroV2)
	}
	if data[0] != introductionV2Version {
		return fmt.Errorf("%w: leading version byte %#x, want %#x", ErrIntroV2Version, data[0], introductionV2Version)
	}
	return binary.Read(bytes.NewReader(data), binary.BigEndian, i)
}

// Sign populates i.Signature and i.SignaturePQ with hybrid signatures
// over the canonical signed message under id's classical and
// post-quantum private keys. The caller is responsible for populating
// every other field of i (including ServerMultisig) before calling.
// Sign sets Version unconditionally so callers can rely on it.
func (i *introductionV2) Sign(id *hybrid.HybridIdentity) error {
	if id == nil || id.EdPriv == nil || id.PQPriv == nil {
		return hybrid.ErrNoPrivateKey
	}
	i.Version = introductionV2Version
	msg := i.signedMsg()
	sigEd := ed25519.Sign(id.EdPriv, msg)
	if len(sigEd) != len(i.Signature) {
		return fmt.Errorf("neverlur: unexpected ed25519 signature length %d", len(sigEd))
	}
	copy(i.Signature[:], sigEd)
	sigPQ, err := pqsig.Sign(id.PQPriv, msg)
	if err != nil {
		return fmt.Errorf("neverlur: pq sign: %w", err)
	}
	if len(sigPQ) != len(i.SignaturePQ) {
		return fmt.Errorf("neverlur: unexpected ml-dsa-65 signature length %d", len(sigPQ))
	}
	copy(i.SignaturePQ[:], sigPQ)
	return nil
}

// Verify returns nil iff all three checks pass:
//
//  1. ed25519.Verify over the canonical signed message under LongTermKey.
//  2. pqsig.Verify (ML-DSA-65) over the same signed message under LongTermKeyPQ.
//  3. bls.VerifyCompressed over the PKG attestation messages under
//     serverKeys, with i.ServerMultisig as the multisig.
//
// Any failing check is rejection. The function reports which check
// failed in the error so operators can diagnose, but the rejection
// decision is the same.
//
// "Both halves required" is constitutional (Principle V). A v2 record
// with one or both signatures zero MUST be rejected; this function does
// not special-case zero signatures.
func (i *introductionV2) Verify(serverKeys []*bls.PublicKey) error {
	if i.Version != introductionV2Version {
		return fmt.Errorf("%w: in-memory version byte %#x", ErrIntroV2Version, i.Version)
	}
	msg := i.signedMsg()

	if !ed25519.Verify(ed25519.PublicKey(i.LongTermKey[:]), msg, i.Signature[:]) {
		return errors.New("neverlur: introduction v2: ed25519 signature did not verify")
	}

	pqPub, err := pqsig.UnpackPublicKey(i.LongTermKeyPQ[:])
	if err != nil {
		return fmt.Errorf("neverlur: introduction v2: bad pq public key: %w", err)
	}
	if !pqsig.Verify(pqPub, msg, i.SignaturePQ[:]) {
		return errors.New("neverlur: introduction v2: ml-dsa-65 signature did not verify")
	}

	attMsgs := make([][]byte, len(serverKeys))
	for j, key := range serverKeys {
		attestation := &pkg.Attestation{
			AttestKey:       key,
			UserIdentity:    &i.Username,
			UserLongTermKey: ed25519.PublicKey(i.LongTermKey[:]),
		}
		attMsgs[j] = attestation.Marshal()
	}
	if !bls.VerifyCompressed(serverKeys, attMsgs, &i.ServerMultisig) {
		return errors.New("neverlur: introduction v2: PKG multisig did not verify")
	}
	return nil
}

// signedMsg returns the canonical byte string covered by Signature and
// SignaturePQ. See docs/wire-introduction-v2.md#signed-message.
func (i *introductionV2) signedMsg() []byte {
	keyHash := sha512.Sum512(append(append([]byte{}, i.LongTermKey[:]...), i.LongTermKeyPQ[:]...))

	buf := new(bytes.Buffer)
	buf.Grow(len(introductionSigPrefix) + 1 + 64 + 32 + pqkem.PublicKeySize + 4 + 64)
	buf.WriteString(introductionSigPrefix)
	buf.WriteByte(i.Version)
	buf.Write(i.Username[:])
	buf.Write(i.DHPublicKey[:])
	buf.Write(i.MLKEMPublicKey[:])
	binary.Write(buf, binary.BigEndian, i.DialingRound)
	buf.Write(keyHash[:])
	return buf.Bytes()
}
