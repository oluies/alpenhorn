// Copyright 2026 The Neverlur Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pqkem

import "testing"

// BenchmarkGenerateKey measures the per-op cost of fresh ML-KEM-768
// keypair generation. Feeds the modeled friend-request handshake cost.
func BenchmarkGenerateKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncapsulate measures the cost of one ML-KEM-768 encapsulation
// against a fresh public key. The keypair is generated once outside the
// timed loop so the benchmark isolates the Encap cost.
func BenchmarkEncapsulate(b *testing.B) {
	pk, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Encapsulate(pk); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecapsulate measures the cost of one ML-KEM-768 decapsulation
// against a fresh ciphertext. The ciphertext is generated once outside the
// timed loop.
func BenchmarkDecapsulate(b *testing.B) {
	pk, sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	ct, _, err := Encapsulate(pk)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decapsulate(sk, ct); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPackPublicKey measures serialization cost of a public key.
func BenchmarkPackPublicKey(b *testing.B) {
	pk, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PackPublicKey(pk)
	}
}

// BenchmarkUnpackPublicKey measures the cost of parsing a packed public key.
func BenchmarkUnpackPublicKey(b *testing.B) {
	pk, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	buf := PackPublicKey(pk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := UnpackPublicKey(buf); err != nil {
			b.Fatal(err)
		}
	}
}
