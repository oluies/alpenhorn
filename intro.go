// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package neverlur

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/oluies/neverlur/addfriend"
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
	// See contracts/introduction-v2.md for the field-by-field layout. v1
	// payloads are 228 bytes (`sizeIntro`); the v2 layout grows by the
	// post-quantum pieces.
	//
	// Layout: 1 (Version) + 64 (Username) + 32 (DHPublicKey)
	//       + pqkem.PublicKeySize (1184)
	//       + 4 (DialingRound) + 32 (LongTermKey)
	//       + pqsig.PublicKeySize (1952)
	//       + 64 (Signature) + pqsig.SignatureSize (3309)
	//       + 32 (ServerMultisig) + 21 (reserved padding)
	//       = 6695.
	SizeIntroV2 = 1 + 64 + 32 + pqkem.PublicKeySize + 4 + 32 + pqsig.PublicKeySize + 64 + pqsig.SignatureSize + 32 + 21
)

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
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, i)
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

// introductionV2 is the hybrid post-quantum form of an Alpenhorn add-friend
// introduction. See contracts/introduction-v2.md and data-model.md E7.
//
// Field order and sizes are part of the wire format; do not reorder.
// Reserved is zero-padding so that the encoded length is a multiple of 7
// (the IBE chunking helper prefers that alignment).
//
// Sign and Verify (and MarshalBinary / UnmarshalBinary) are intentionally
// unimplemented in this foundational change — they belong to phases US1
// (KEM-related fields) and US2 (signature-related fields) per the tasks
// plan. The stubs panic so a caller cannot accidentally trust an unsigned
// v2 introduction.
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

// MarshalBinary will be implemented as part of the US1/US2 work. The
// fixed-width layout is defined in contracts/introduction-v2.md.
func (i *introductionV2) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("introductionV2.MarshalBinary: not yet implemented (foundational phase scope only)")
}

// UnmarshalBinary will be implemented as part of the US1/US2 work.
func (i *introductionV2) UnmarshalBinary(data []byte) error {
	return fmt.Errorf("introductionV2.UnmarshalBinary: not yet implemented (foundational phase scope only)")
}
