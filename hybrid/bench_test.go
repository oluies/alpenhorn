// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package hybrid

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/oluies/neverlur/pqkem"
)

// BenchmarkCombineKEM measures the per-call combiner cost. Run for all
// three contexts since each has its own HKDF info string and there's no
// reason to assume they cost the same.
func BenchmarkCombineKEM(b *testing.B) {
	ssX := bytes.Repeat([]byte{0x55}, X25519SharedSize)
	ssM := bytes.Repeat([]byte{0xaa}, MLKEMSharedSize)
	transcript := []byte("benchmark transcript, representative length, 128+ bytes here. " +
		"hybrid handshake binds initiator pubs + responder pubs + round number + identity pair.")

	for _, ctx := range []string{ContextFriendRequest, ContextKeywheelSeed, ContextEdTLSSession} {
		b.Run(ctx, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := CombineKEM(ctx, transcript, ssX, ssM); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFoundationalHandshake measures the full per-friend-request
// CPU cost of the foundational primitive stack: X25519 keygen + ECDH on
// both sides, ML-KEM-768 keygen + encap + decap, and one CombineKEM call
// on each side. This is the pre-protocol-overhead estimate of the
// per-handshake cost.
//
// SC-007 budget ceiling: 1.25x the pre-PQ baseline. This benchmark
// produces the input number for the modeled comparison.
func BenchmarkFoundationalHandshake(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Initiator: ephemeral X25519 + ML-KEM pubs.
		var initX [32]byte
		rand.Read(initX[:])
		initX[0] &= 248
		initX[31] &= 127
		initX[31] |= 64
		initXPub, err := curve25519.X25519(initX[:], curve25519.Basepoint)
		if err != nil {
			b.Fatal(err)
		}
		initMLPub, initMLPriv, err := pqkem.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}

		// Responder: ephemeral X25519, encapsulates to initiator's ML pub.
		var respX [32]byte
		rand.Read(respX[:])
		respX[0] &= 248
		respX[31] &= 127
		respX[31] |= 64
		respXPub, err := curve25519.X25519(respX[:], curve25519.Basepoint)
		if err != nil {
			b.Fatal(err)
		}
		ct, respML, err := pqkem.Encapsulate(initMLPub)
		if err != nil {
			b.Fatal(err)
		}
		respXShared, err := curve25519.X25519(respX[:], initXPub)
		if err != nil {
			b.Fatal(err)
		}

		// Responder derives the session secret.
		tr := []byte("benchmark transcript")
		if _, err := CombineKEM(ContextFriendRequest, tr, respXShared, respML); err != nil {
			b.Fatal(err)
		}

		// Initiator finishes: X25519 ECDH + Decapsulate + Combine.
		initXShared, err := curve25519.X25519(initX[:], respXPub)
		if err != nil {
			b.Fatal(err)
		}
		initML, err := pqkem.Decapsulate(initMLPriv, ct)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := CombineKEM(ContextFriendRequest, tr, initXShared, initML); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadIdentityFile measures the cost of loading a hybrid
// identity file from disk including the R4 binding re-derivation.
// This is the startup tax paid by every server binary on every boot.
func BenchmarkLoadIdentityFile(b *testing.B) {
	id, err := GenerateHybridIdentity()
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	path := filepath.Join(dir, "bench"+IdentityFileSuffix)
	if err := WriteIdentityFile(path, id); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadIdentityFile(path); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyBinding measures the cost of re-running the R4 binding
// check on an already-loaded identity. Called whenever an identity is
// re-validated.
func BenchmarkVerifyBinding(b *testing.B) {
	id, err := GenerateHybridIdentity()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := id.VerifyBinding(); err != nil {
			b.Fatal(err)
		}
	}
}
