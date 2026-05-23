// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// BenchmarkGenerateKey measures fresh ML-DSA-65 keypair generation cost.
func BenchmarkGenerateKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeriveFromEd25519Seed measures the R4 binding derivation cost.
// This is the startup tax paid on every identity load.
func BenchmarkDeriveFromEd25519Seed(b *testing.B) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	seed := edPriv.Seed()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := DeriveFromEd25519Seed(seed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSign measures the cost of one randomized ML-DSA-65 signature.
// The randomization makes runtime variable; numbers should be read as
// distributions, not single points.
func BenchmarkSign(b *testing.B) {
	_, sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark payload of moderate length, representative of a SignedConfig digest input")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(sk, msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignDeterministic measures the deterministic-signing path.
func BenchmarkSignDeterministic(b *testing.B) {
	_, sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark payload")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SignDeterministic(sk, msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify measures the cost of one ML-DSA-65 signature verification.
func BenchmarkVerify(b *testing.B) {
	pk, sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark payload of moderate length, representative of a SignedConfig digest input")
	sig, err := Sign(sk, msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(pk, msg, sig) {
			b.Fatal("Verify returned false on a valid signature")
		}
	}
}
